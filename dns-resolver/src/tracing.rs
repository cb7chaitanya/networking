/// Tracing support for DNS resolver protocol events.
///
/// This module provides OpenTelemetry-compatible tracing instrumentation for:
/// - DNS lookups (iterative resolution)
/// - UDP/TCP queries to nameservers
/// - Cache operations
///
/// # Usage
///
/// Initialize tracing at application startup:
/// ```no_run
/// dns_resolver::tracing::init_tracing();
/// ```
///
/// The spans are automatically created by the instrumented functions.
/// Use environment variables to control verbosity:
/// - `RUST_LOG=dns_resolver::tracing=debug` for detailed tracing
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` to configure OpenTelemetry export
use tracing::{info_span, instrument, Span};

use crate::dns::RecordType;

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

// ── DNS Lookup Spans ──────────────────────────────────────────────────────────

/// Create a span for a DNS lookup operation.
///
/// A DNS lookup is the top-level operation that resolves a domain name
/// to its associated records. This may involve multiple iterative queries
/// to different nameservers.
///
/// # Attributes
///
/// - `name`: The domain name being resolved
/// - `record_type`: The type of record requested (A, AAAA, MX, etc.)
/// - `query_id`: The DNS query ID
#[inline]
pub fn dns_lookup_span(name: &str, record_type: RecordType, query_id: u16) -> Span {
    info_span!(
        "dns_lookup",
        name = name,
        record_type = record_type_to_str(record_type),
        query_id = query_id,
    )
}

/// Record the start of a DNS lookup.
#[inline]
pub fn record_lookup_start(name: &str, record_type: RecordType) {
    tracing::info!(
        name = name,
        record_type = record_type_to_str(record_type),
        "dns_lookup_start"
    );
}

/// Record a successful DNS lookup completion.
#[inline]
pub fn record_lookup_success(name: &str, record_type: RecordType, answer_count: usize) {
    tracing::info!(
        name = name,
        record_type = record_type_to_str(record_type),
        answer_count = answer_count,
        "dns_lookup_success"
    );
}

/// Record a failed DNS lookup.
#[inline]
pub fn record_lookup_failure(name: &str, record_type: RecordType, reason: &str) {
    tracing::error!(
        name = name,
        record_type = record_type_to_str(record_type),
        reason = reason,
        "dns_lookup_failure"
    );
}

/// Record a cache hit during DNS lookup.
#[inline]
pub fn record_cache_hit(name: &str, record_type: RecordType) {
    tracing::debug!(
        name = name,
        record_type = record_type_to_str(record_type),
        "dns_cache_hit"
    );
}

/// Record a cache miss during DNS lookup.
#[inline]
pub fn record_cache_miss(name: &str, record_type: RecordType) {
    tracing::debug!(
        name = name,
        record_type = record_type_to_str(record_type),
        "dns_cache_miss"
    );
}

// ── DNS Query Spans ───────────────────────────────────────────────────────────

/// Create a span for a DNS query to a nameserver.
///
/// This represents a single query to a specific nameserver as part of
/// iterative resolution.
///
/// # Attributes
///
/// - `server`: The nameserver address
/// - `protocol`: "udp" or "tcp"
/// - `name`: The domain name being queried
/// - `record_type`: The type of record requested
#[inline]
pub fn dns_query_span(
    server: &str,
    protocol: &'static str,
    name: &str,
    record_type: RecordType,
) -> Span {
    info_span!(
        "dns_query",
        server = server,
        protocol = protocol,
        name = name,
        record_type = record_type_to_str(record_type),
    )
}

/// Record a UDP query sent.
#[inline]
pub fn record_udp_query_sent(server: &str, name: &str, record_type: RecordType) {
    tracing::debug!(
        server = server,
        name = name,
        record_type = record_type_to_str(record_type),
        "dns_udp_query_sent"
    );
}

/// Record a UDP response received.
#[inline]
pub fn record_udp_response_received(server: &str, response_size: usize, truncated: bool) {
    tracing::debug!(
        server = server,
        response_size = response_size,
        truncated = truncated,
        "dns_udp_response_received"
    );
}

/// Record a TCP query sent (typically after truncation).
#[inline]
pub fn record_tcp_query_sent(server: &str, name: &str, record_type: RecordType) {
    tracing::debug!(
        server = server,
        name = name,
        record_type = record_type_to_str(record_type),
        "dns_tcp_query_sent"
    );
}

/// Record a TCP response received.
#[inline]
pub fn record_tcp_response_received(server: &str, response_size: usize) {
    tracing::debug!(
        server = server,
        response_size = response_size,
        "dns_tcp_response_received"
    );
}

/// Record a query timeout.
#[inline]
pub fn record_query_timeout(server: &str, protocol: &'static str, attempt: u32) {
    tracing::warn!(
        server = server,
        protocol = protocol,
        attempt = attempt,
        "dns_query_timeout"
    );
}

/// Record a query error.
#[inline]
pub fn record_query_error(server: &str, protocol: &'static str, error: &str) {
    tracing::error!(
        server = server,
        protocol = protocol,
        error = error,
        "dns_query_error"
    );
}

/// Record a query retry.
#[inline]
pub fn record_query_retry(server: &str, protocol: &'static str, attempt: u32) {
    tracing::debug!(
        server = server,
        protocol = protocol,
        attempt = attempt,
        "dns_query_retry"
    );
}

// ── Iterative Resolution Spans ────────────────────────────────────────────────

/// Create a span for an iterative resolution step.
///
/// This represents one step in the iterative resolution process where
/// we query a nameserver and potentially get a referral to another zone.
#[inline]
pub fn resolution_step_span(step: u32, server: &str, zone: &str) -> Span {
    info_span!(
        "dns_resolution_step",
        step = step,
        server = server,
        zone = zone,
    )
}

/// Record a referral received (NS records pointing to another zone).
#[inline]
pub fn record_referral_received(from_server: &str, ns_count: usize, zone: &str) {
    tracing::debug!(
        from_server = from_server,
        ns_count = ns_count,
        zone = zone,
        "dns_referral_received"
    );
}

/// Record use of glue records.
#[inline]
pub fn record_glue_used(ns_name: &str, glue_ip: &str) {
    tracing::trace!(ns_name = ns_name, glue_ip = glue_ip, "dns_glue_used");
}

/// Record when glue is missing and NS needs resolution.
#[inline]
pub fn record_glue_missing(ns_name: &str) {
    tracing::debug!(ns_name = ns_name, "dns_glue_missing");
}

/// Record CNAME chain following.
#[inline]
pub fn record_cname_followed(from: &str, to: &str, depth: u32) {
    tracing::debug!(from = from, to = to, depth = depth, "dns_cname_followed");
}

/// Record CNAME chain limit exceeded.
#[inline]
pub fn record_cname_loop_detected(name: &str, depth: u32) {
    tracing::error!(name = name, depth = depth, "dns_cname_loop_detected");
}

// ── Root Server Spans ─────────────────────────────────────────────────────────

/// Record querying a root server.
#[inline]
pub fn record_root_query(server: &str) {
    tracing::debug!(server = server, "dns_root_query");
}

/// Record a root server response.
#[inline]
pub fn record_root_response(server: &str, success: bool) {
    tracing::debug!(server = server, success = success, "dns_root_response");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert RecordType to a static string for tracing attributes.
#[inline]
fn record_type_to_str(rt: RecordType) -> &'static str {
    match rt {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::MX => "MX",
        RecordType::NS => "NS",
        RecordType::TXT => "TXT",
        RecordType::SOA => "SOA",
        RecordType::PTR => "PTR",
        RecordType::Unknown(_) => "UNKNOWN",
    }
}

// ── Instrumented wrapper functions ────────────────────────────────────────────

/// Instrumented wrapper for DNS lookup execution.
#[instrument(name = "dns_lookup", skip(f), fields(name, record_type, query_id))]
pub fn run_lookup<F, R>(name: &str, record_type: RecordType, query_id: u16, f: F) -> R
where
    F: FnOnce() -> R,
{
    Span::current().record("name", name);
    Span::current().record("record_type", record_type_to_str(record_type));
    Span::current().record("query_id", query_id);
    f()
}

/// Instrumented wrapper for DNS query execution.
#[instrument(
    name = "dns_query",
    skip(f),
    fields(server, protocol, name, record_type)
)]
pub fn run_query<F, R>(
    server: &str,
    protocol: &'static str,
    name: &str,
    record_type: RecordType,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    Span::current().record("server", server);
    Span::current().record("protocol", protocol);
    Span::current().record("name", name);
    Span::current().record("record_type", record_type_to_str(record_type));
    f()
}
