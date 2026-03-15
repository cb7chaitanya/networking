//! Integration tests for DNS resolver tracing instrumentation.
//!
//! These tests verify that spans and events are correctly emitted
//! for DNS lookups, queries, and iterative resolution.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dns_resolver::tracing::{
    dns_lookup_span, dns_query_span, record_cache_hit, record_cache_miss, record_cname_followed,
    record_cname_loop_detected, record_glue_missing, record_glue_used, record_lookup_failure,
    record_lookup_start, record_lookup_success, record_query_error, record_query_retry,
    record_query_timeout, record_referral_received, record_root_query, record_root_response,
    record_tcp_query_sent, record_tcp_response_received, record_udp_query_sent,
    record_udp_response_received, resolution_step_span, run_lookup, run_query,
};
use dns_resolver::RecordType;

use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

// ── Test Helpers ──────────────────────────────────────────────────────────────

/// A test subscriber that counts span entries.
struct CountingLayer {
    span_count: Arc<AtomicUsize>,
    event_count: Arc<AtomicUsize>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountingLayer {
    fn on_new_span(
        &self,
        _attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.span_count.fetch_add(1, Ordering::SeqCst);
    }

    fn on_event(
        &self,
        _event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.event_count.fetch_add(1, Ordering::SeqCst);
    }
}

fn test_subscriber() -> (impl tracing::Subscriber, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let span_count = Arc::new(AtomicUsize::new(0));
    let event_count = Arc::new(AtomicUsize::new(0));
    let layer = CountingLayer {
        span_count: span_count.clone(),
        event_count: event_count.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    (subscriber, span_count, event_count)
}

// ── Span Tests ────────────────────────────────────────────────────────────────

#[test]
fn dns_lookup_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = dns_lookup_span("example.com", RecordType::A, 12345).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn dns_query_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = dns_query_span("8.8.8.8", "udp", "example.com", RecordType::A).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn resolution_step_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = resolution_step_span(1, "198.41.0.4", "com.").entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

// ── Lookup Event Tests ────────────────────────────────────────────────────────

#[test]
fn record_lookup_start_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_lookup_start("example.com", RecordType::A);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_lookup_success_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_lookup_success("example.com", RecordType::A, 2);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_lookup_failure_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_lookup_failure("example.com", RecordType::A, "NXDOMAIN");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Cache Event Tests ─────────────────────────────────────────────────────────

#[test]
fn record_cache_hit_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_cache_hit("example.com", RecordType::A);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_cache_miss_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_cache_miss("example.com", RecordType::A);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── UDP Query Event Tests ─────────────────────────────────────────────────────

#[test]
fn record_udp_query_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_udp_query_sent("8.8.8.8", "example.com", RecordType::A);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_udp_response_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_udp_response_received("8.8.8.8", 512, false);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_udp_response_truncated() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_udp_response_received("8.8.8.8", 512, true);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── TCP Query Event Tests ─────────────────────────────────────────────────────

#[test]
fn record_tcp_query_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_tcp_query_sent("8.8.8.8", "example.com", RecordType::A);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_tcp_response_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_tcp_response_received("8.8.8.8", 2048);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Query Error Event Tests ───────────────────────────────────────────────────

#[test]
fn record_query_timeout_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_query_timeout("8.8.8.8", "udp", 2);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_query_error_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_query_error("8.8.8.8", "udp", "connection refused");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_query_retry_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_query_retry("8.8.8.8", "udp", 3);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Iterative Resolution Event Tests ──────────────────────────────────────────

#[test]
fn record_referral_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_referral_received("198.41.0.4", 4, "com.");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_glue_used_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_glue_used("a.gtld-servers.net.", "192.5.6.30");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_glue_missing_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_glue_missing("ns1.example.com.");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── CNAME Event Tests ─────────────────────────────────────────────────────────

#[test]
fn record_cname_followed_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_cname_followed("www.example.com", "example.com", 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_cname_loop_detected_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_cname_loop_detected("loop.example.com", 10);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Root Server Event Tests ───────────────────────────────────────────────────

#[test]
fn record_root_query_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_root_query("198.41.0.4");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_root_response_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_root_response("198.41.0.4", true);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Instrumented Wrapper Tests ────────────────────────────────────────────────

#[test]
fn run_lookup_executes_closure() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let result = run_lookup("example.com", RecordType::A, 12345, || 42);
        assert_eq!(result, 42);
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn run_query_executes_closure() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let result = run_query("8.8.8.8", "udp", "example.com", RecordType::A, || "success");
        assert_eq!(result, "success");
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

// ── Combined Flow Tests ───────────────────────────────────────────────────────

#[test]
fn simple_cached_lookup() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span = dns_lookup_span("example.com", RecordType::A, 12345).entered();

        record_lookup_start("example.com", RecordType::A);
        record_cache_hit("example.com", RecordType::A);
        record_lookup_success("example.com", RecordType::A, 1);

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 3);
    });
}

#[test]
fn iterative_resolution_full_trace() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        // Start lookup
        let _lookup = dns_lookup_span("example.com", RecordType::A, 12345).entered();
        record_lookup_start("example.com", RecordType::A);
        record_cache_miss("example.com", RecordType::A);

        // Query root server
        let _step1 = resolution_step_span(1, "198.41.0.4", ".").entered();
        record_root_query("198.41.0.4");
        record_udp_query_sent("198.41.0.4", "example.com", RecordType::A);
        record_udp_response_received("198.41.0.4", 512, false);
        record_root_response("198.41.0.4", true);
        record_referral_received("198.41.0.4", 13, "com.");

        // Query TLD server with glue
        let _step2 = resolution_step_span(2, "192.5.6.30", "com.").entered();
        record_glue_used("a.gtld-servers.net.", "192.5.6.30");
        record_udp_query_sent("192.5.6.30", "example.com", RecordType::A);
        record_udp_response_received("192.5.6.30", 256, false);
        record_referral_received("192.5.6.30", 2, "example.com.");

        // Query authoritative server
        let _step3 = resolution_step_span(3, "93.184.216.34", "example.com.").entered();
        record_udp_query_sent("93.184.216.34", "example.com", RecordType::A);
        record_udp_response_received("93.184.216.34", 64, false);

        record_lookup_success("example.com", RecordType::A, 1);

        // 4 spans (1 lookup + 3 resolution steps)
        assert_eq!(span_count.load(Ordering::SeqCst), 4);
        // 14 events (2 start + 5 root + 4 tld + 2 auth + 1 success)
        assert_eq!(event_count.load(Ordering::SeqCst), 14);
    });
}

#[test]
fn truncated_udp_fallback_to_tcp() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _query =
            dns_query_span("8.8.8.8", "udp", "large.example.com", RecordType::TXT).entered();

        record_udp_query_sent("8.8.8.8", "large.example.com", RecordType::TXT);
        record_udp_response_received("8.8.8.8", 512, true);
        record_tcp_query_sent("8.8.8.8", "large.example.com", RecordType::TXT);
        record_tcp_response_received("8.8.8.8", 4096);

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn cname_chain_resolution() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_lookup_start("www.example.com", RecordType::A);
        record_cname_followed("www.example.com", "web.example.com", 1);
        record_cname_followed("web.example.com", "cdn.example.com", 2);
        record_lookup_success("cdn.example.com", RecordType::A, 1);

        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn cname_loop_detection() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_lookup_start("loop.example.com", RecordType::A);
        for i in 1..=10 {
            record_cname_followed(
                &format!("loop{}.example.com", i - 1),
                &format!("loop{}.example.com", i),
                i,
            );
        }
        record_cname_loop_detected("loop.example.com", 10);
        record_lookup_failure("loop.example.com", RecordType::A, "CNAME loop detected");

        assert_eq!(event_count.load(Ordering::SeqCst), 13);
    });
}

#[test]
fn query_with_retries() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_udp_query_sent("8.8.8.8", "example.com", RecordType::A);
        record_query_timeout("8.8.8.8", "udp", 1);
        record_query_retry("8.8.8.8", "udp", 2);
        record_udp_query_sent("8.8.8.8", "example.com", RecordType::A);
        record_query_timeout("8.8.8.8", "udp", 2);
        record_query_retry("8.8.8.8", "udp", 3);
        record_udp_query_sent("8.8.8.8", "example.com", RecordType::A);
        record_udp_response_received("8.8.8.8", 64, false);

        assert_eq!(event_count.load(Ordering::SeqCst), 8);
    });
}

#[test]
fn query_failure() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _lookup = dns_lookup_span("example.com", RecordType::A, 12345).entered();

        record_lookup_start("example.com", RecordType::A);
        record_udp_query_sent("8.8.8.8", "example.com", RecordType::A);
        record_query_error("8.8.8.8", "udp", "connection refused");
        record_lookup_failure("example.com", RecordType::A, "all nameservers failed");

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn glue_missing_requires_resolution() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_referral_received("192.5.6.30", 2, "example.com.");
        record_glue_missing("ns1.example.net.");
        // Would need to resolve ns1.example.net. before continuing
        record_udp_query_sent("8.8.8.8", "ns1.example.net.", RecordType::A);
        record_udp_response_received("8.8.8.8", 64, false);

        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn all_record_types() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_lookup_start("example.com", RecordType::A);
        record_lookup_start("example.com", RecordType::AAAA);
        record_lookup_start("example.com", RecordType::MX);
        record_lookup_start("example.com", RecordType::NS);
        record_lookup_start("example.com", RecordType::TXT);
        record_lookup_start("example.com", RecordType::SOA);
        record_lookup_start("www.example.com", RecordType::CNAME);
        record_lookup_start("1.0.0.127.in-addr.arpa", RecordType::PTR);

        assert_eq!(event_count.load(Ordering::SeqCst), 8);
    });
}
