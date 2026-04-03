//! Fuzz target for `WireNodeEntry::decode`.
//!
//! Feeds arbitrary byte streams into the wire entry decoder.  If decode
//! succeeds, re-encodes and verifies the roundtrip is consistent.
#![no_main]

use libfuzzer_sys::fuzz_target;
use gossip_membership::message::WireNodeEntry;

fuzz_target!(|data: &[u8]| {
    match WireNodeEntry::decode(data) {
        Some((entry, consumed)) => {
            // consumed must not exceed input length.
            assert!(consumed <= data.len());

            // Re-encode and verify fields survive the roundtrip.
            let mut buf = Vec::new();
            entry.encode_into(&mut buf);
            assert_eq!(buf.len(), entry.wire_len());

            let (entry2, consumed2) = WireNodeEntry::decode(&buf)
                .expect("re-encode/re-decode roundtrip must succeed");
            assert_eq!(consumed2, buf.len());
            assert_eq!(entry, entry2);
        }
        None => {
            // Rejected — fine.
        }
    }
});
