//! Integration tests for TCP handshake tracing instrumentation.
//!
//! These tests verify that spans and events are correctly emitted
//! for TCP 3-way handshake, connection lifecycle, and data transfer.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tcp_over_udp::tracing::{
    connection_span, record_ack_received, record_ack_sent, record_connection_closed,
    record_data_received, record_data_sent, record_fin_received, record_fin_sent,
    record_handshake_ack_received, record_handshake_ack_sent, record_handshake_complete,
    record_handshake_failed, record_handshake_timeout, record_retransmit, record_rst_received,
    record_rst_sent, record_state_transition, record_syn_ack_received, record_syn_ack_sent,
    record_syn_received, record_syn_sent, run_handshake, tcp_handshake_span,
};

use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

// ── Test Helpers ──────────────────────────────────────────────────────────────

fn make_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

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
fn tcp_handshake_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span =
            tcp_handshake_span("client", make_addr(5000), Some(make_addr(6000)), 12345).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn tcp_handshake_span_without_peer() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = tcp_handshake_span("server", make_addr(5000), None, 12345).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn connection_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = connection_span(make_addr(5000), make_addr(6000)).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

// ── Handshake Event Tests ─────────────────────────────────────────────────────

#[test]
fn record_syn_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_syn_sent(make_addr(6000), 12345, 1460);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_syn_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_syn_received(make_addr(5000), 12345, Some(1460));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_syn_ack_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_syn_ack_sent(make_addr(5000), 54321, 12346, 1460);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_syn_ack_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_syn_ack_received(make_addr(6000), 54321, 12346, Some(1460));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_handshake_ack_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_handshake_ack_sent(make_addr(6000), 54322);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_handshake_ack_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_handshake_ack_received(make_addr(5000), 54322);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_handshake_complete_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_handshake_complete(make_addr(6000), 1460, Some(7), Some(7));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_handshake_failed_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_handshake_failed(Some(make_addr(6000)), "max retries exceeded");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_handshake_timeout_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_handshake_timeout(make_addr(6000), 2, "syn");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Connection Lifecycle Event Tests ──────────────────────────────────────────

#[test]
fn record_state_transition_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_state_transition("syn_sent", "established");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_fin_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_fin_sent(make_addr(6000), 99999);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_fin_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_fin_received(make_addr(5000), 88888);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_rst_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_rst_sent(make_addr(6000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_rst_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_rst_received(make_addr(5000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_connection_closed_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_connection_closed(make_addr(6000), true);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Data Transfer Event Tests ─────────────────────────────────────────────────

#[test]
fn record_data_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_data_sent(make_addr(6000), 12345, 1024);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_data_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_data_received(make_addr(5000), 54321, 512, true);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_ack_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_ack_sent(make_addr(6000), 12346);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_ack_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_ack_received(make_addr(5000), 54322);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_retransmit_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_retransmit(make_addr(6000), 12345, 3);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Instrumented Wrapper Tests ────────────────────────────────────────────────

#[test]
fn run_handshake_executes_closure() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let result = run_handshake(
            "client",
            make_addr(5000),
            Some(make_addr(6000)),
            12345,
            || 42,
        );
        assert_eq!(result, 42);
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

// ── Combined Flow Tests ───────────────────────────────────────────────────────

#[test]
fn successful_client_handshake_sequence() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span =
            tcp_handshake_span("client", make_addr(5000), Some(make_addr(6000)), 12345).entered();

        record_syn_sent(make_addr(6000), 12345, 1460);
        record_syn_ack_received(make_addr(6000), 54321, 12346, Some(1460));
        record_handshake_ack_sent(make_addr(6000), 54322);
        record_handshake_complete(make_addr(6000), 1460, Some(7), Some(7));

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn successful_server_handshake_sequence() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span = tcp_handshake_span("server", make_addr(6000), None, 54321).entered();

        record_syn_received(make_addr(5000), 12345, Some(1460));
        record_syn_ack_sent(make_addr(5000), 54321, 12346, 1460);
        record_handshake_ack_received(make_addr(5000), 54322);
        record_handshake_complete(make_addr(5000), 1460, Some(7), Some(7));

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn handshake_failure_with_retries() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span =
            tcp_handshake_span("client", make_addr(5000), Some(make_addr(6000)), 12345).entered();

        record_syn_sent(make_addr(6000), 12345, 1460);
        record_handshake_timeout(make_addr(6000), 1, "syn");
        record_syn_sent(make_addr(6000), 12345, 1460);
        record_handshake_timeout(make_addr(6000), 2, "syn");
        record_handshake_failed(Some(make_addr(6000)), "max retries exceeded");

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 5);
    });
}

#[test]
fn graceful_connection_close() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span = connection_span(make_addr(5000), make_addr(6000)).entered();

        record_state_transition("established", "fin_wait_1");
        record_fin_sent(make_addr(6000), 99999);
        record_fin_received(make_addr(6000), 88888);
        record_state_transition("fin_wait_1", "time_wait");
        record_connection_closed(make_addr(6000), true);

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 5);
    });
}

#[test]
fn connection_reset() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span = connection_span(make_addr(5000), make_addr(6000)).entered();

        record_rst_received(make_addr(6000));
        record_connection_closed(make_addr(6000), false);

        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn data_transfer_with_retransmission() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_data_sent(make_addr(6000), 12345, 1024);
        record_retransmit(make_addr(6000), 12345, 1);
        record_retransmit(make_addr(6000), 12345, 2);
        record_ack_received(make_addr(6000), 13369);

        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}

#[test]
fn full_connection_lifecycle() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        // Handshake
        let _handshake =
            tcp_handshake_span("client", make_addr(5000), Some(make_addr(6000)), 12345).entered();
        record_syn_sent(make_addr(6000), 12345, 1460);
        record_syn_ack_received(make_addr(6000), 54321, 12346, Some(1460));
        record_handshake_ack_sent(make_addr(6000), 54322);
        record_handshake_complete(make_addr(6000), 1460, Some(7), Some(7));

        // Data transfer
        let _conn = connection_span(make_addr(5000), make_addr(6000)).entered();
        record_data_sent(make_addr(6000), 12346, 100);
        record_ack_received(make_addr(6000), 12446);
        record_data_received(make_addr(6000), 54322, 200, true);
        record_ack_sent(make_addr(6000), 54522);

        // Graceful close
        record_fin_sent(make_addr(6000), 12446);
        record_fin_received(make_addr(6000), 54522);
        record_connection_closed(make_addr(6000), true);

        assert_eq!(span_count.load(Ordering::SeqCst), 2);
        assert_eq!(event_count.load(Ordering::SeqCst), 11);
    });
}
