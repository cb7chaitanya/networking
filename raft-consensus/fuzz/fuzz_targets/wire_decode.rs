//! Fuzz `wire::decode` on arbitrary byte sequences.
//!
//! Properties verified on every input:
//!
//! 1. **No panic** — `wire::decode` must handle any byte sequence without
//!    panicking; returning `Err` is always acceptable.
//!
//! 2. **Roundtrip idempotency** — if a byte sequence successfully decodes to an
//!    `Rpc`, then re-encoding it must:
//!    a. Produce bytes that decode successfully (no partial/corrupt state).
//!    b. Re-encode to the *same* bytes (the codec is deterministic).
//!
//! 3. **Term consistency** — the term extracted from the decoded value must
//!    survive a full encode→decode cycle unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use raft_consensus::wire;

fuzz_target!(|data: &[u8]| {
    // ── Property 1: no panic on arbitrary bytes ───────────────────────────────
    let Ok(rpc) = wire::decode(data) else {
        return; // Err is always allowed.
    };

    // ── Property 2a: encode of a decoded value must be re-decodable ───────────
    let encoded = wire::encode(&rpc);
    let rpc2 = wire::decode(&encoded)
        .expect("decode(encode(rpc)) must not fail for a valid Rpc");

    // ── Property 2b: encoding is deterministic (idempotent under roundtrip) ───
    let encoded2 = wire::encode(&rpc2);
    assert_eq!(
        encoded, encoded2,
        "encode(decode(encode(decode(bytes)))) != encode(decode(bytes))"
    );

    // ── Property 3: term survives the roundtrip unchanged ─────────────────────
    assert_eq!(
        rpc.term(),
        rpc2.term(),
        "term changed across encode/decode roundtrip"
    );
});
