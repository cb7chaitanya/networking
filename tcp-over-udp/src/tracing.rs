/// Tracing support for TCP-over-UDP protocol events.
///
/// This module provides OpenTelemetry-compatible tracing instrumentation for:
/// - TCP 3-way handshake (SYN, SYN-ACK, ACK)
/// - Connection establishment and teardown
/// - Data transfer and retransmissions
///
/// # Usage
///
/// Initialize tracing at application startup:
/// ```no_run
/// tcp_over_udp::tracing::init_tracing();
/// ```
///
/// The spans are automatically created by the instrumented functions.
/// Use environment variables to control verbosity:
/// - `RUST_LOG=tcp_over_udp::tracing=debug` for detailed tracing
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` to configure OpenTelemetry export

use std::net::SocketAddr;
use tracing::{info_span, instrument, Span};

// ── Initialization ────────────────────────────────────────────────────────────

/// Initialize the tracing subscriber with OpenTelemetry support.
///
/// This sets up a layered subscriber with:
/// - Console output (via tracing-subscriber fmt layer)
/// - OpenTelemetry export (when OTEL_EXPORTER_OTLP_ENDPOINT is set)
///
/// Call this once at application startup before any tracing occurs.
pub fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

// ── TCP Handshake Spans ───────────────────────────────────────────────────────

/// Create a span for the entire TCP 3-way handshake process.
///
/// This span encompasses the full connection establishment:
/// - Client: SYN → SYN-ACK → ACK
/// - Server: SYN ← SYN-ACK → ACK ←
///
/// # Attributes
///
/// - `role`: "client" or "server"
/// - `local_addr`: Local socket address
/// - `peer_addr`: Remote socket address (if known)
/// - `isn`: Initial sequence number
#[inline]
pub fn tcp_handshake_span(
    role: &'static str,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    isn: u32,
) -> Span {
    info_span!(
        "tcp_handshake",
        role = role,
        local_addr = %local_addr,
        peer_addr = peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string()).as_str(),
        isn = isn,
    )
}

/// Record a SYN packet sent (client initiating connection).
#[inline]
pub fn record_syn_sent(peer_addr: SocketAddr, seq: u32, mss: u16) {
    tracing::debug!(
        peer_addr = %peer_addr,
        seq = seq,
        mss = mss,
        "syn_sent"
    );
}

/// Record a SYN packet received (server receiving connection request).
#[inline]
pub fn record_syn_received(peer_addr: SocketAddr, seq: u32, mss: Option<u16>) {
    tracing::debug!(
        peer_addr = %peer_addr,
        seq = seq,
        mss = mss.unwrap_or(0),
        "syn_received"
    );
}

/// Record a SYN-ACK packet sent (server responding to SYN).
#[inline]
pub fn record_syn_ack_sent(peer_addr: SocketAddr, seq: u32, ack: u32, mss: u16) {
    tracing::debug!(
        peer_addr = %peer_addr,
        seq = seq,
        ack = ack,
        mss = mss,
        "syn_ack_sent"
    );
}

/// Record a SYN-ACK packet received (client receiving server response).
#[inline]
pub fn record_syn_ack_received(peer_addr: SocketAddr, seq: u32, ack: u32, mss: Option<u16>) {
    tracing::debug!(
        peer_addr = %peer_addr,
        seq = seq,
        ack = ack,
        mss = mss.unwrap_or(0),
        "syn_ack_received"
    );
}

/// Record the final ACK sent (client completing handshake).
#[inline]
pub fn record_handshake_ack_sent(peer_addr: SocketAddr, ack: u32) {
    tracing::debug!(
        peer_addr = %peer_addr,
        ack = ack,
        "handshake_ack_sent"
    );
}

/// Record the final ACK received (server handshake complete).
#[inline]
pub fn record_handshake_ack_received(peer_addr: SocketAddr, ack: u32) {
    tracing::debug!(
        peer_addr = %peer_addr,
        ack = ack,
        "handshake_ack_received"
    );
}

/// Record handshake completion with negotiated parameters.
#[inline]
pub fn record_handshake_complete(
    peer_addr: SocketAddr,
    negotiated_mss: u16,
    snd_wscale: Option<u8>,
    rcv_wscale: Option<u8>,
) {
    tracing::info!(
        peer_addr = %peer_addr,
        negotiated_mss = negotiated_mss,
        snd_wscale = snd_wscale.unwrap_or(0),
        rcv_wscale = rcv_wscale.unwrap_or(0),
        "handshake_complete"
    );
}

/// Record handshake failure.
#[inline]
pub fn record_handshake_failed(peer_addr: Option<SocketAddr>, reason: &str) {
    tracing::error!(
        peer_addr = peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string()).as_str(),
        reason = reason,
        "handshake_failed"
    );
}

/// Record handshake timeout (retransmission).
#[inline]
pub fn record_handshake_timeout(peer_addr: SocketAddr, attempt: u32, phase: &'static str) {
    tracing::warn!(
        peer_addr = %peer_addr,
        attempt = attempt,
        phase = phase,
        "handshake_timeout"
    );
}

// ── Connection Lifecycle Spans ────────────────────────────────────────────────

/// Create a span for the connection lifecycle.
///
/// This span covers the entire connection from establishment to teardown.
#[inline]
pub fn connection_span(local_addr: SocketAddr, peer_addr: SocketAddr) -> Span {
    info_span!(
        "tcp_connection",
        local_addr = %local_addr,
        peer_addr = %peer_addr,
    )
}

/// Record connection state transition.
#[inline]
pub fn record_state_transition(from: &'static str, to: &'static str) {
    tracing::debug!(
        from_state = from,
        to_state = to,
        "state_transition"
    );
}

/// Record FIN sent (initiating graceful close).
#[inline]
pub fn record_fin_sent(peer_addr: SocketAddr, seq: u32) {
    tracing::debug!(
        peer_addr = %peer_addr,
        seq = seq,
        "fin_sent"
    );
}

/// Record FIN received (peer initiating close).
#[inline]
pub fn record_fin_received(peer_addr: SocketAddr, seq: u32) {
    tracing::debug!(
        peer_addr = %peer_addr,
        seq = seq,
        "fin_received"
    );
}

/// Record RST sent (connection abort).
#[inline]
pub fn record_rst_sent(peer_addr: SocketAddr) {
    tracing::warn!(
        peer_addr = %peer_addr,
        "rst_sent"
    );
}

/// Record RST received (peer aborted connection).
#[inline]
pub fn record_rst_received(peer_addr: SocketAddr) {
    tracing::warn!(
        peer_addr = %peer_addr,
        "rst_received"
    );
}

/// Record connection closed.
#[inline]
pub fn record_connection_closed(peer_addr: SocketAddr, graceful: bool) {
    tracing::info!(
        peer_addr = %peer_addr,
        graceful = graceful,
        "connection_closed"
    );
}

// ── Data Transfer Spans ───────────────────────────────────────────────────────

/// Record data segment sent.
#[inline]
pub fn record_data_sent(peer_addr: SocketAddr, seq: u32, len: usize) {
    tracing::trace!(
        peer_addr = %peer_addr,
        seq = seq,
        len = len,
        "data_sent"
    );
}

/// Record data segment received.
#[inline]
pub fn record_data_received(peer_addr: SocketAddr, seq: u32, len: usize, accepted: bool) {
    tracing::trace!(
        peer_addr = %peer_addr,
        seq = seq,
        len = len,
        accepted = accepted,
        "data_received"
    );
}

/// Record ACK sent.
#[inline]
pub fn record_ack_sent(peer_addr: SocketAddr, ack: u32) {
    tracing::trace!(
        peer_addr = %peer_addr,
        ack = ack,
        "ack_sent"
    );
}

/// Record ACK received.
#[inline]
pub fn record_ack_received(peer_addr: SocketAddr, ack: u32) {
    tracing::trace!(
        peer_addr = %peer_addr,
        ack = ack,
        "ack_received"
    );
}

/// Record retransmission.
#[inline]
pub fn record_retransmit(peer_addr: SocketAddr, seq: u32, attempt: u32) {
    tracing::warn!(
        peer_addr = %peer_addr,
        seq = seq,
        attempt = attempt,
        "retransmit"
    );
}

// ── Instrumented wrapper functions ────────────────────────────────────────────

/// Instrumented wrapper for TCP handshake execution.
#[instrument(
    name = "tcp_handshake",
    skip(f),
    fields(role, local_addr, peer_addr, isn)
)]
pub fn run_handshake<F, R>(
    role: &'static str,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    isn: u32,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    Span::current().record("role", role);
    Span::current().record("local_addr", tracing::field::display(local_addr));
    Span::current().record(
        "peer_addr",
        tracing::field::display(
            peer_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
    );
    Span::current().record("isn", isn);
    f()
}

/// Async instrumented wrapper for TCP handshake execution.
#[instrument(
    name = "tcp_handshake",
    skip(f),
    fields(role, local_addr, peer_addr, isn)
)]
pub async fn run_handshake_async<F, Fut, R>(
    role: &'static str,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    isn: u32,
    f: F,
) -> R
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = R>,
{
    Span::current().record("role", role);
    Span::current().record("local_addr", tracing::field::display(local_addr));
    Span::current().record(
        "peer_addr",
        tracing::field::display(
            peer_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ),
    );
    Span::current().record("isn", isn);
    f().await
}
