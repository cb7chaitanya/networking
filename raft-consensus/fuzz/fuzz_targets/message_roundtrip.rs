//! Structured-input roundtrip fuzz target.
//!
//! Rather than feeding raw bytes to the decoder, this target *constructs*
//! valid `Rpc` values from fuzz-controlled field data and verifies that
//! encode → decode → encode is byte-for-byte idempotent.
//!
//! This exercises the encoder thoroughly (all 11 message types, edge-case
//! field values such as `u64::MAX`, zero-length entry slices, etc.) while
//! leaving the detection of decode-side panics to `wire_decode`.
//!
//! Properties verified:
//!
//! 1. `wire::encode` never panics on an in-memory `Rpc`.
//! 2. `wire::decode(wire::encode(rpc))` always succeeds.
//! 3. `wire::encode(decode(encode(rpc))) == wire::encode(rpc)` (idempotent).
//! 4. The term field is preserved across the roundtrip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use raft_consensus::{
    log::LogEntry,
    message::{
        AppendEntriesArgs, AppendEntriesReply, InstallSnapshotArgs, InstallSnapshotReply,
        PreVoteArgs, PreVoteReply, ReadIndexArgs, ReadIndexReply, RequestVoteArgs,
        RequestVoteReply, Rpc, TimeoutNowArgs,
    },
    wire,
};

// ── Fuzz-byte reader helpers ──────────────────────────────────────────────────

/// Read a `u64` (little-endian) starting at `offset` in `data`.
/// Pads with zeros if there are fewer than 8 bytes remaining.
fn u64_at(data: &[u8], offset: usize) -> u64 {
    let end = (offset + 8).min(data.len());
    let src = &data[offset.min(data.len())..end];
    let mut buf = [0u8; 8];
    buf[..src.len()].copy_from_slice(src);
    u64::from_le_bytes(buf)
}

fn bool_at(data: &[u8], offset: usize) -> bool {
    data.get(offset).map_or(false, |b| b & 1 != 0)
}

/// Build a valid `Rpc` from raw fuzz bytes.
///
/// The first byte selects the message type (mod 11); the remaining bytes
/// provide field values.  For `AppendEntries`, entries are extracted from
/// the fuzz data with a capped count so the target remains fast.
fn build_rpc(data: &[u8]) -> Option<Rpc> {
    if data.is_empty() {
        return None;
    }

    Some(match data[0] % 11 {
        // 0 — RequestVote
        0 => Rpc::RequestVote(RequestVoteArgs {
            term:           u64_at(data, 1),
            candidate_id:   u64_at(data, 9),
            last_log_index: u64_at(data, 17),
            last_log_term:  u64_at(data, 25),
        }),

        // 1 — RequestVoteResponse
        1 => Rpc::RequestVoteResponse(RequestVoteReply {
            term:        u64_at(data, 1),
            vote_granted: bool_at(data, 9),
        }),

        // 2 — AppendEntries (variable-length entries derived from fuzz bytes)
        2 => {
            // Cap at 32 entries to keep the benchmark fast while still
            // exercising interesting sizes.
            let n_entries = (data.get(1).copied().unwrap_or(0) as usize) % 33;
            let mut entries = Vec::with_capacity(n_entries);
            let mut pos = 2usize;

            for _ in 0..n_entries {
                let term = u64_at(data, pos).max(1); // term must be ≥ 1
                pos += 8;
                // Data length: 0–63 bytes.
                let data_len = (data.get(pos).copied().unwrap_or(0) as usize) % 64;
                pos += 1;
                // Clamp start before computing end so start <= end holds even
                // when pos has advanced past data.len().
                let start = pos.min(data.len());
                let end = (start + data_len).min(data.len());
                let payload = data[start..end].to_vec();
                pos = start + data_len;
                entries.push(LogEntry { term, data: payload });
            }

            Rpc::AppendEntries(AppendEntriesArgs {
                term:           u64_at(data, 1),
                leader_id:      u64_at(data, 9),
                prev_log_index: u64_at(data, 17),
                prev_log_term:  u64_at(data, 25),
                leader_commit:  u64_at(data, 33),
                entries,
            })
        }

        // 3 — AppendEntriesResponse
        3 => Rpc::AppendEntriesResponse(AppendEntriesReply {
            term:        u64_at(data, 1),
            success:     bool_at(data, 9),
            match_index: u64_at(data, 10),
        }),

        // 4 — PreVote
        4 => Rpc::PreVote(PreVoteArgs {
            term:           u64_at(data, 1),
            candidate_id:   u64_at(data, 9),
            last_log_index: u64_at(data, 17),
            last_log_term:  u64_at(data, 25),
        }),

        // 5 — PreVoteResponse
        5 => Rpc::PreVoteResponse(PreVoteReply {
            term:         u64_at(data, 1),
            vote_granted: bool_at(data, 9),
        }),

        // 6 — InstallSnapshot (snapshot data from fuzz bytes, capped at 4 KiB)
        6 => {
            let payload_len = (u64_at(data, 41) as usize) % (4 * 1024);
            let start = 49_usize.min(data.len());
            let end = (start + payload_len).min(data.len());
            Rpc::InstallSnapshot(InstallSnapshotArgs {
                term:                 u64_at(data, 1),
                leader_id:            u64_at(data, 9),
                last_included_index:  u64_at(data, 17),
                last_included_term:   u64_at(data, 25),
                offset:               u64_at(data, 33),
                data:                 data[start..end].to_vec(),
                done:                 bool_at(data, 41),
            })
        }

        // 7 — InstallSnapshotResponse
        7 => Rpc::InstallSnapshotResponse(InstallSnapshotReply {
            term: u64_at(data, 1),
        }),

        // 8 — ReadIndexRequest
        8 => Rpc::ReadIndexRequest(ReadIndexArgs {
            term:      u64_at(data, 1),
            reader_id: u64_at(data, 9),
        }),

        // 9 — ReadIndexResponse
        9 => Rpc::ReadIndexResponse(ReadIndexReply {
            term:       u64_at(data, 1),
            read_index: u64_at(data, 9),
        }),

        // 10 — TimeoutNow
        _ => Rpc::TimeoutNow(TimeoutNowArgs {
            term:      u64_at(data, 1),
            leader_id: u64_at(data, 9),
        }),
    })
}

// ── Fuzz target ───────────────────────────────────────────────────────────────

fuzz_target!(|data: &[u8]| {
    let Some(rpc) = build_rpc(data) else { return };

    // Property 1: encode never panics for an in-memory Rpc.
    let encoded = wire::encode(&rpc);

    // Property 2: decode of our own encoded bytes must always succeed.
    let rpc2 = wire::decode(&encoded)
        .expect("decode(encode(rpc)) must succeed for all valid Rpc values");

    // Property 3: re-encoding must produce the same bytes (codec determinism).
    let encoded2 = wire::encode(&rpc2);
    assert_eq!(
        encoded, encoded2,
        "encode(decode(encode(rpc))) != encode(rpc): codec is not idempotent"
    );

    // Property 4: term survives the roundtrip.
    assert_eq!(
        rpc.term(),
        rpc2.term(),
        "term changed across encode/decode roundtrip"
    );
});
