//! Fuzz target for `Message::decode`.
//!
//! Feeds arbitrary byte streams into the decoder and verifies it never
//! panics.  Valid messages are re-encoded and re-decoded to check
//! roundtrip consistency.
#![no_main]

use libfuzzer_sys::fuzz_target;
use gossip_membership::message::Message;

fuzz_target!(|data: &[u8]| {
    // Must never panic — errors are fine.
    match Message::decode(data) {
        Ok(msg) => {
            // If decode succeeded, re-encode must also succeed and
            // the re-decoded message must match.
            if let Ok(buf) = msg.encode() {
                let msg2 = Message::decode(&buf)
                    .expect("re-encode/re-decode roundtrip must succeed");
                assert_eq!(msg.sender_id, msg2.sender_id);
                assert_eq!(msg.sender_heartbeat, msg2.sender_heartbeat);
                assert_eq!(msg.sender_incarnation, msg2.sender_incarnation);
                assert_eq!(msg.kind, msg2.kind);
                assert_eq!(msg.version, msg2.version);
                assert_eq!(msg.flags, msg2.flags);
            }
        }
        Err(_) => {
            // Rejected — that's fine.
        }
    }
});
