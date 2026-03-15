/// Tracing support for gossip-membership protocol events.
///
/// This module provides OpenTelemetry-compatible tracing instrumentation for:
/// - Gossip rounds (dissemination cycles)
/// - Failure detection probes (PING/ACK cycles)
/// - Membership changes (node status transitions)
///
/// # Usage
///
/// Initialize tracing at application startup:
/// ```no_run
/// gossip_membership::tracing::init_tracing();
/// ```
///
/// The spans are automatically created by the instrumented functions.
/// Use environment variables to control verbosity:
/// - `RUST_LOG=gossip_membership::tracing=debug` for detailed tracing
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` to configure OpenTelemetry export
use std::net::SocketAddr;
use tracing::{info_span, instrument, Span};

use crate::node::{NodeId, NodeStatus};

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

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Initialize tracing with OpenTelemetry OTLP exporter.
///
/// This configures the full OpenTelemetry pipeline for distributed tracing.
/// Traces are exported to the endpoint specified by `OTEL_EXPORTER_OTLP_ENDPOINT`
/// environment variable (defaults to `http://localhost:4317`).
///
/// # Arguments
///
/// * `service_name` - The service name to use in traces (e.g., "gossip-node-1")
#[cfg(feature = "otel")]
pub fn init_tracing_with_otel(service_name: &str) {
    use opentelemetry::global;
    use opentelemetry_sdk::trace::TracerProvider;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
            opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                "service.name",
                service_name.to_string(),
            )]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .expect("failed to initialize OTLP tracer");

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();
}

// ── Gossip Round Spans ────────────────────────────────────────────────────────

/// Create a span for a gossip round.
///
/// A gossip round is one cycle of the epidemic dissemination protocol where
/// the local node sends its membership digest to a set of randomly selected
/// peers.
///
/// # Attributes
///
/// - `node_id`: The local node's identifier
/// - `round`: Monotonic round counter
/// - `target_count`: Number of peers selected for this round
/// - `fanout`: Number of entries included in the gossip message
#[inline]
pub fn gossip_round_span(node_id: NodeId, round: u64, target_count: usize, fanout: usize) -> Span {
    info_span!(
        "gossip_round",
        node_id = node_id,
        round = round,
        target_count = target_count,
        fanout = fanout,
    )
}

/// Record a gossip message sent to a peer.
///
/// Called within a `gossip_round` span for each target peer.
#[inline]
pub fn record_gossip_sent(target_id: NodeId, target_addr: SocketAddr) {
    tracing::debug!(
        target_id = target_id,
        target_addr = %target_addr,
        "gossip_sent"
    );
}

/// Record a gossip message received from a peer.
#[inline]
pub fn record_gossip_received(sender_id: NodeId, sender_addr: SocketAddr, entry_count: usize) {
    tracing::debug!(
        sender_id = sender_id,
        sender_addr = %sender_addr,
        entry_count = entry_count,
        "gossip_received"
    );
}

// ── Probe Spans ───────────────────────────────────────────────────────────────

/// Create a span for a failure detection probe.
///
/// A probe is the SWIM failure detection mechanism: send PING, wait for ACK.
/// If no ACK arrives within timeout, escalate to indirect probe (PING_REQ).
///
/// # Attributes
///
/// - `node_id`: The local node's identifier (prober)
/// - `target_id`: The node being probed
/// - `target_addr`: Network address of the probe target
/// - `phase`: "direct" or "indirect"
#[inline]
pub fn probe_span(
    node_id: NodeId,
    target_id: NodeId,
    target_addr: SocketAddr,
    phase: &'static str,
) -> Span {
    info_span!(
        "probe",
        node_id = node_id,
        target_id = target_id,
        target_addr = %target_addr,
        phase = phase,
    )
}

/// Record a PING sent to a target.
#[inline]
pub fn record_ping_sent(target_id: NodeId, target_addr: SocketAddr) {
    tracing::debug!(
        target_id = target_id,
        target_addr = %target_addr,
        "ping_sent"
    );
}

/// Record an ACK received from a target.
#[inline]
pub fn record_ack_received(sender_id: NodeId, sender_addr: SocketAddr) {
    tracing::debug!(
        sender_id = sender_id,
        sender_addr = %sender_addr,
        "ack_received"
    );
}

/// Record a probe timeout (no ACK received).
#[inline]
pub fn record_probe_timeout(target_id: NodeId, phase: &'static str) {
    tracing::warn!(target_id = target_id, phase = phase, "probe_timeout");
}

/// Record escalation from direct to indirect probe.
#[inline]
pub fn record_probe_escalation(target_id: NodeId, intermediary_count: usize) {
    tracing::info!(
        target_id = target_id,
        intermediary_count = intermediary_count,
        "probe_escalation"
    );
}

/// Record a PING_REQ sent via intermediary.
#[inline]
pub fn record_ping_req_sent(
    target_id: NodeId,
    target_addr: SocketAddr,
    intermediary_addr: SocketAddr,
) {
    tracing::debug!(
        target_id = target_id,
        target_addr = %target_addr,
        intermediary_addr = %intermediary_addr,
        "ping_req_sent"
    );
}

// ── Membership Change Spans ───────────────────────────────────────────────────

/// Create a span for a membership change event.
///
/// Membership changes occur when a node's status transitions between
/// Alive, Suspect, and Dead states.
///
/// # Attributes
///
/// - `node_id`: The node whose status changed
/// - `old_status`: Previous status (or "new" for newly discovered nodes)
/// - `new_status`: Current status after the change
#[inline]
pub fn membership_change_span(
    node_id: NodeId,
    old_status: Option<NodeStatus>,
    new_status: NodeStatus,
) -> Span {
    let old_str = old_status.map(|s| status_to_str(s)).unwrap_or("new");
    info_span!(
        "membership_change",
        node_id = node_id,
        old_status = old_str,
        new_status = status_to_str(new_status),
    )
}

/// Record a new node joining the cluster.
#[inline]
pub fn record_node_joined(node_id: NodeId, addr: SocketAddr) {
    tracing::info!(
        node_id = node_id,
        addr = %addr,
        "node_joined"
    );
}

/// Record a node transitioning to Suspect status.
#[inline]
pub fn record_node_suspected(node_id: NodeId) {
    tracing::warn!(node_id = node_id, "node_suspected");
}

/// Record a node being declared Dead.
#[inline]
pub fn record_node_dead(node_id: NodeId) {
    tracing::error!(node_id = node_id, "node_dead");
}

/// Record a node rejoining after being Dead (incarnation bump).
#[inline]
pub fn record_node_rejoined(node_id: NodeId, addr: SocketAddr, new_incarnation: u32) {
    tracing::info!(
        node_id = node_id,
        addr = %addr,
        new_incarnation = new_incarnation,
        "node_rejoined"
    );
}

/// Record a suspicion refutation (local node refuting its own suspected status).
#[inline]
pub fn record_suspicion_refuted(node_id: NodeId, old_incarnation: u32, new_incarnation: u32) {
    tracing::info!(
        node_id = node_id,
        old_incarnation = old_incarnation,
        new_incarnation = new_incarnation,
        "suspicion_refuted"
    );
}

/// Record a graceful LEAVE message received.
#[inline]
pub fn record_node_left(node_id: NodeId, addr: SocketAddr) {
    tracing::info!(
        node_id = node_id,
        addr = %addr,
        "node_left"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert NodeStatus to a static string for tracing attributes.
#[inline]
fn status_to_str(status: NodeStatus) -> &'static str {
    match status {
        NodeStatus::Alive => "alive",
        NodeStatus::Suspect => "suspect",
        NodeStatus::Dead => "dead",
    }
}

// ── Instrumented wrapper functions ────────────────────────────────────────────

/// Instrumented wrapper for gossip round execution.
///
/// Use this to wrap the gossip round logic for automatic span management:
/// ```ignore
/// tracing::run_gossip_round(node_id, round, || {
///     // gossip round logic here
/// });
/// ```
#[instrument(
    name = "gossip_round",
    skip(f),
    fields(node_id, round, target_count, fanout)
)]
pub fn run_gossip_round<F, R>(
    node_id: NodeId,
    round: u64,
    target_count: usize,
    fanout: usize,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    Span::current().record("node_id", node_id);
    Span::current().record("round", round);
    Span::current().record("target_count", target_count);
    Span::current().record("fanout", fanout);
    f()
}

/// Instrumented wrapper for probe execution.
#[instrument(
    name = "probe",
    skip(f),
    fields(node_id, target_id, target_addr, phase)
)]
pub fn run_probe<F, R>(
    node_id: NodeId,
    target_id: NodeId,
    target_addr: SocketAddr,
    phase: &'static str,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    Span::current().record("node_id", node_id);
    Span::current().record("target_id", target_id);
    Span::current().record("target_addr", tracing::field::display(target_addr));
    Span::current().record("phase", phase);
    f()
}
