//! Snapshot-focused fuzz target.
//!
//! `InstallSnapshot` carries an opaque byte blob whose size is controlled by
//! the leader.  A bug in the length-prefix handling (e.g. an unchecked cast,
//! an off-by-one, or an allocation without a size cap) could cause OOM, an
//! integer overflow, or a panic.  This target exercises those paths with two
//! complementary strategies:
//!
//! ## Strategy A — tag-prefixed arbitrary bytes
//!
//! Prepend the `InstallSnapshot` tag byte (0x07) to the raw fuzz data so the
//! decoder always enters the snapshot branch.  Everything after the tag is
//! still arbitrary, so the fuzzer can discover any framing bug (truncated
//! headers, oversized `data_len`, missing `done` byte, etc.).
//!
//! ## Strategy B — valid frame, fuzz-controlled payload
//!
//! Build a syntactically correct `InstallSnapshot` whose `data` blob comes
//! entirely from the fuzzer.  This ensures the decoder processes actual payload
//! bytes rather than rejecting the frame at the header stage.  Field values
//! (term, index, offset, done) also come from fuzz bytes so we reach boundary
//! conditions such as `u64::MAX`, `offset != 0`, and `done = false`.
//!
//! Properties verified on both paths:
//!
//! 1. **No panic** — `wire::decode` must not panic on any byte sequence.
//! 2. **Roundtrip idempotency** — `encode(decode(encode(x))) == encode(x)`.
//! 3. **Term preservation** — the term survives a full encode/decode cycle.
#![no_main]

use libfuzzer_sys::fuzz_target;
use raft_consensus::{
    message::{InstallSnapshotArgs, Rpc},
    wire,
};

/// Wire tag for `InstallSnapshot` (must match `wire.rs`).
const TAG_INSTALL_SNAPSHOT: u8 = 7;

fn roundtrip_check(rpc: Rpc) {
    let encoded = wire::encode(&rpc);

    let rpc2 = wire::decode(&encoded)
        .expect("decode(encode(snapshot_rpc)) must not fail");

    let encoded2 = wire::encode(&rpc2);
    assert_eq!(encoded, encoded2, "snapshot roundtrip produced different bytes");

    assert_eq!(
        rpc.term(),
        rpc2.term(),
        "term changed across snapshot roundtrip"
    );
}

fuzz_target!(|data: &[u8]| {
    // ── Strategy A: tag-prefixed arbitrary bytes ──────────────────────────────
    {
        let mut tagged = Vec::with_capacity(1 + data.len());
        tagged.push(TAG_INSTALL_SNAPSHOT);
        tagged.extend_from_slice(data);

        // Must not panic.  Err is acceptable.
        if let Ok(rpc) = wire::decode(&tagged) {
            roundtrip_check(rpc);
        }
    }

    // ── Strategy B: well-formed frame, fuzz-controlled payload ────────────────
    {
        let read_u64 = |off: usize| -> u64 {
            let end = (off + 8).min(data.len());
            let src = &data[off.min(data.len())..end];
            let mut buf = [0u8; 8];
            buf[..src.len()].copy_from_slice(src);
            u64::from_le_bytes(buf)
        };

        let term                = read_u64(0);
        let leader_id           = read_u64(8);
        let last_included_index = read_u64(16);
        let last_included_term  = read_u64(24);
        let offset              = read_u64(32);
        let done                = data.get(32).map_or(true, |b| b & 1 != 0);

        // Cap payload to keep memory bounded regardless of fuzzer input length.
        const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;
        let payload_start = 33_usize.min(data.len());
        let payload_end   = (payload_start + MAX_SNAPSHOT_BYTES).min(data.len());
        let snapshot_data = data[payload_start..payload_end].to_vec();

        let rpc = Rpc::InstallSnapshot(InstallSnapshotArgs {
            term,
            leader_id,
            last_included_index,
            last_included_term,
            offset,
            data: snapshot_data,
            done,
        });

        roundtrip_check(rpc);
    }
});
