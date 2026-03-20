//! Packet trace logging for debugging.
//!
//! When enabled via [`enable()`], every packet sent or received through the
//! [`Socket`](crate::socket::Socket) layer is printed as a one-line trace:
//!
//! ```text
//! [TRACE] TX 127.0.0.1:9000 → 127.0.0.1:50123  SYN       seq=100 ack=0   win=65535
//! [TRACE] RX 127.0.0.1:50123 → 127.0.0.1:9000   SYN-ACK   seq=200 ack=101 win=65535
//! [TRACE] TX 127.0.0.1:9000 → 127.0.0.1:50123  ACK       seq=101 ack=201 win=65535
//! [TRACE] TX 127.0.0.1:9000 → 127.0.0.1:50123  DATA      seq=101 ack=201 win=65535 len=5
//! [TRACE] RETRANSMIT seq=101 len=5
//! [TRACE] TX 127.0.0.1:9000 → 127.0.0.1:50123  FIN-ACK   seq=106 ack=201 win=65535
//! ```
//!
//! # Usage
//!
//! ```ignore
//! tcp_over_udp::trace::enable();
//! // Now all socket I/O is traced to stderr via eprintln!
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::packet::{flags, Packet};

/// Global trace switch.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable packet trace logging.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Returns `true` when tracing is active.
#[inline]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Format a flags byte (with OPT already stripped) as a human-readable label.
fn flag_label(base: u8) -> &'static str {
    if base == flags::SYN | flags::ACK {
        "SYN-ACK"
    } else if base == flags::SYN {
        "SYN"
    } else if base == flags::FIN | flags::ACK {
        "FIN-ACK"
    } else if base == flags::FIN {
        "FIN"
    } else if base == flags::RST | flags::ACK {
        "RST-ACK"
    } else if base == flags::RST {
        "RST"
    } else if base == flags::ACK {
        // ACK-only: could be pure ACK or DATA (payload distinguishes them)
        "ACK"
    } else {
        "???"
    }
}

/// Classify a packet as a human-readable label, taking payload into account.
///
/// DATA segments carry the ACK flag plus a non-empty payload, so we label
/// them `DATA` instead of `ACK`.
fn packet_label(pkt: &Packet) -> &'static str {
    let base = pkt.header.flags & !flags::OPT;
    if base == flags::ACK && !pkt.payload.is_empty() {
        return "DATA";
    }
    flag_label(base)
}

/// Log a transmitted packet.
pub fn log_tx(local: SocketAddr, dest: SocketAddr, pkt: &Packet) {
    if !is_enabled() {
        return;
    }
    let h = &pkt.header;
    let label = packet_label(pkt);
    let len = pkt.payload.len();
    if len > 0 {
        eprintln!(
            "[TRACE] TX {local} → {dest}  {label:<10} seq={} ack={} win={} len={len}",
            h.seq, h.ack, h.window
        );
    } else {
        eprintln!(
            "[TRACE] TX {local} → {dest}  {label:<10} seq={} ack={} win={}",
            h.seq, h.ack, h.window
        );
    }
}

/// Log a received packet.
pub fn log_rx(local: SocketAddr, from: SocketAddr, pkt: &Packet) {
    if !is_enabled() {
        return;
    }
    let h = &pkt.header;
    let label = packet_label(pkt);
    let len = pkt.payload.len();
    if len > 0 {
        eprintln!(
            "[TRACE] RX {from} → {local}  {label:<10} seq={} ack={} win={} len={len}",
            h.seq, h.ack, h.window
        );
    } else {
        eprintln!(
            "[TRACE] RX {from} → {local}  {label:<10} seq={} ack={} win={}",
            h.seq, h.ack, h.window
        );
    }
}

/// Log a retransmission event.
pub fn log_retransmit(pkt: &Packet) {
    if !is_enabled() {
        return;
    }
    let h = &pkt.header;
    let len = pkt.payload.len();
    eprintln!(
        "[TRACE] RETRANSMIT seq={} len={len}",
        h.seq
    );
}
