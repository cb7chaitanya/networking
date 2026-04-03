/// Benchmarks for gossip message compression.
///
/// Measures CPU vs bandwidth tradeoffs at various cluster sizes:
/// encode-only vs encode+compress, and decode vs decompress+decode.
///
/// For entry counts that exceed the 1400-byte UDP payload limit when
/// uncompressed, we benchmark raw serialize+compress vs serialize-only
/// to isolate compression overhead.
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use gossip_membership::compression;
use gossip_membership::message::{build_gossip, status, Message, WireNodeEntry, NODE_ENTRY_V4_LEN};

fn make_entries(count: u64) -> Vec<WireNodeEntry> {
    (0..count)
        .map(|i| WireNodeEntry {
            node_id: i * 1000 + 42,
            heartbeat: i as u32 * 7,
            incarnation: i as u32,
            status: match i % 3 {
                0 => status::ALIVE,
                1 => status::SUSPECT,
                _ => status::DEAD,
            },
            addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1)),
                7000 + (i % 1000) as u16,
            ),
        })
        .collect()
}

/// Serialize entries into raw bytes (without header/checksum).
fn serialize_entries(entries: &[WireNodeEntry]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entries.len() * NODE_ENTRY_V4_LEN);
    for e in entries {
        e.encode_into(&mut buf);
    }
    buf
}

/// Benchmark full encode path for sizes that fit in a single datagram,
/// and raw serialize+compress for larger sizes.
fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for count in [10, 50, 100, 200] {
        let entries = make_entries(count);
        let raw_size = count as usize * NODE_ENTRY_V4_LEN;

        if raw_size <= 1400 {
            let msg = build_gossip(1, 1, 0, entries.clone());
            group.bench_with_input(
                BenchmarkId::new("uncompressed", count),
                &msg,
                |b, msg| {
                    b.iter(|| black_box(msg.encode_opts(false).unwrap()));
                },
            );
            group.bench_with_input(
                BenchmarkId::new("compressed", count),
                &msg,
                |b, msg| {
                    b.iter(|| black_box(msg.encode_opts(true).unwrap()));
                },
            );
        } else {
            group.bench_with_input(
                BenchmarkId::new("serialize_only", count),
                &entries,
                |b, entries| {
                    b.iter(|| black_box(serialize_entries(entries)));
                },
            );
            group.bench_with_input(
                BenchmarkId::new("serialize_compress", count),
                &entries,
                |b, entries| {
                    b.iter(|| {
                        let raw = serialize_entries(entries);
                        black_box(compression::compress(&raw))
                    });
                },
            );
        }
    }
    group.finish();
}

/// Benchmark decode path.
fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");
    for count in [10, 50, 100, 200] {
        let entries = make_entries(count);
        let raw_size = count as usize * NODE_ENTRY_V4_LEN;

        if raw_size <= 1400 {
            let msg = build_gossip(1, 1, 0, entries);

            let uncompressed = msg.encode_opts(false).unwrap();
            group.bench_with_input(
                BenchmarkId::new("uncompressed", count),
                &uncompressed,
                |b, buf| {
                    b.iter(|| black_box(Message::decode(buf).unwrap()));
                },
            );

            let compressed = msg.encode_opts(true).unwrap();
            group.bench_with_input(
                BenchmarkId::new("compressed", count),
                &compressed,
                |b, buf| {
                    b.iter(|| black_box(Message::decode(buf).unwrap()));
                },
            );
        } else {
            let raw = serialize_entries(&entries);
            let compressed = compression::compress(&raw);
            group.bench_with_input(
                BenchmarkId::new("decompress_parse", count),
                &compressed,
                |b, data| {
                    b.iter(|| {
                        let decompressed = compression::decompress(data).unwrap();
                        let mut off = 0;
                        let mut parsed = Vec::new();
                        while off < decompressed.len() {
                            if let Some((entry, consumed)) = WireNodeEntry::decode(&decompressed[off..]) {
                                parsed.push(entry);
                                off += consumed;
                            } else {
                                break;
                            }
                        }
                        black_box(parsed)
                    });
                },
            );
        }
    }
    group.finish();
}

/// Report compression ratios for all sizes.
fn bench_compression_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_ratio");
    for count in [10, 50, 100, 200] {
        let entries = make_entries(count);
        let raw = serialize_entries(&entries);
        let compressed = compression::compress(&raw);
        let ratio = compressed.len() as f64 / raw.len() as f64;
        println!(
            "{count} entries: raw={} bytes, compressed={} bytes, ratio={:.2} ({:.0}% savings)",
            raw.len(),
            compressed.len(),
            ratio,
            (1.0 - ratio) * 100.0
        );
        group.bench_with_input(
            BenchmarkId::new("compress", count),
            &raw,
            |b, data| {
                b.iter(|| black_box(compression::compress(data)));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_compression_ratio);
criterion_main!(benches);
