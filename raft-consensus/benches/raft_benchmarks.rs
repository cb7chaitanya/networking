use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use raft_consensus::{
    log::{InMemoryLog, LogEntry, RaftLog},
    message::{AppendEntriesArgs, Envelope, InstallSnapshotArgs, RequestVoteArgs, Rpc},
    node::{ClusterConfig, RaftNode},
    wire,
};

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Entry sizes exercised across every benchmark group.
const SIZES: [usize; 3] = [10, 100, 1000];

/// Bytes per log entry payload. Chosen to be representative without being huge.
const PAYLOAD: usize = 64;

fn make_entries(n: usize) -> Vec<LogEntry> {
    (1..=n)
        .map(|i| LogEntry {
            term: ((i / 10) + 1) as u64,
            data: vec![(i & 0xff) as u8; PAYLOAD],
        })
        .collect()
}

fn make_append_entries(n: usize) -> Rpc {
    Rpc::AppendEntries(AppendEntriesArgs {
        term: 1,
        leader_id: 1,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: make_entries(n),
        leader_commit: 0,
    })
}

/// Minimal Raft config for benchmark nodes — short timeouts so we don't wait
/// on timers during commit-advancement setup.
fn bench_config() -> ClusterConfig {
    ClusterConfig {
        election_timeout_min: 5,
        election_timeout_max: 10,
        heartbeat_interval: 2,
        pre_vote: false,
    }
}

/// Return a single-node leader ready to accept proposals (no-op already
/// committed, applied queue drained).
fn single_node_leader() -> RaftNode {
    let mut node = RaftNode::new(1, vec![], bench_config());
    node.start_election(); // immediate win — single voter
    let _ = node.drain_messages();
    let _ = node.drain_applied();
    node
}

// ── AppendEntries encode ──────────────────────────────────────────────────────

fn bench_append_entries_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_entries_encode");
    for n in SIZES {
        let rpc = make_append_entries(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &rpc, |b, rpc| {
            b.iter(|| wire::encode(black_box(rpc)));
        });
    }
    group.finish();
}

// ── AppendEntries decode ──────────────────────────────────────────────────────

fn bench_append_entries_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_entries_decode");
    for n in SIZES {
        let bytes = wire::encode(&make_append_entries(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &bytes, |b, bytes| {
            b.iter(|| wire::decode(black_box(bytes)).unwrap());
        });
    }
    group.finish();
}

// ── RequestVote encode/decode ─────────────────────────────────────────────────
// RequestVote is fixed-size (33 bytes); benchmarked once, not parametrised by
// entry count.  Placed in a group so it appears alongside the other codecs in
// the HTML report.

fn bench_request_vote_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_vote_encode");
    let rpc = Rpc::RequestVote(RequestVoteArgs {
        term: 7,
        candidate_id: 2,
        last_log_index: 1_000,
        last_log_term: 6,
    });
    // Still use BenchmarkId so the report is consistent with other groups.
    group.bench_with_input(BenchmarkId::from_parameter("fixed"), &rpc, |b, rpc| {
        b.iter(|| wire::encode(black_box(rpc)));
    });
    group.finish();
}

fn bench_request_vote_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_vote_decode");
    let bytes = wire::encode(&Rpc::RequestVote(RequestVoteArgs {
        term: 7,
        candidate_id: 2,
        last_log_index: 1_000,
        last_log_term: 6,
    }));
    group.bench_with_input(BenchmarkId::from_parameter("fixed"), &bytes, |b, bytes| {
        b.iter(|| wire::decode(black_box(bytes)).unwrap());
    });
    group.finish();
}

// ── Log append ───────────────────────────────────────────────────────────────

fn bench_log_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_append");
    for n in SIZES {
        let entries = make_entries(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &entries, |b, entries| {
            b.iter_batched(
                InMemoryLog::new,
                |mut log| {
                    for e in entries {
                        log.append(black_box(e.clone()));
                    }
                    log // return so the log is not dropped inside the measured region
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ── Commit advancement ────────────────────────────────────────────────────────
// Measures proposing N entries on a single-node leader and draining the
// resulting applied queue.  In a single-node cluster the leader is also the
// only voter, so every entry commits immediately inside `propose()`.

fn bench_commit_advancement(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_advancement");
    for n in SIZES {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                single_node_leader,
                |mut node| {
                    for i in 0..n {
                        node.propose(vec![black_box(i as u8); PAYLOAD]);
                    }
                    let _ = node.drain_messages();
                    let applied = node.drain_applied();
                    (node, applied) // keep both alive until Criterion drops them
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ── Snapshot installation ─────────────────────────────────────────────────────
// Measures delivering a single-chunk InstallSnapshot RPC to a fresh follower.
// Snapshot data is scaled as N × PAYLOAD bytes to stay proportional to an
// equivalent compacted log of N entries.

fn bench_snapshot_install(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_install");
    for n in SIZES {
        let data = vec![0xab_u8; n * PAYLOAD];
        let envelope = Envelope {
            from: 1,
            to: 2,
            payload: Rpc::InstallSnapshot(InstallSnapshotArgs {
                term: 5,
                leader_id: 1,
                last_included_index: n as u64,
                last_included_term: 1,
                offset: 0,
                data: data.clone(),
                done: true,
            }),
        };

        group.bench_with_input(BenchmarkId::from_parameter(n), &envelope, |b, envelope| {
            b.iter_batched(
                // Fresh follower node for every sample — avoids snapshot-already-applied
                // short-circuiting which would eliminate the work we want to measure.
                || RaftNode::new(2, vec![1], bench_config()),
                |mut node| {
                    node.step(black_box(envelope.clone()));
                    node
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ── Criterion entry point ─────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_append_entries_encode,
    bench_append_entries_decode,
    bench_request_vote_encode,
    bench_request_vote_decode,
    bench_log_append,
    bench_commit_advancement,
    bench_snapshot_install,
);
criterion_main!(benches);
