//! Integration tests for tracing instrumentation.
//!
//! These tests verify that spans and events are correctly emitted
//! for gossip rounds, probes, and membership changes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use gossip_membership::node::NodeStatus;
use gossip_membership::tracing::{
    gossip_round_span, membership_change_span, probe_span, record_ack_received,
    record_gossip_received, record_gossip_sent, record_node_dead, record_node_joined,
    record_node_left, record_node_rejoined, record_node_suspected, record_ping_req_sent,
    record_ping_sent, record_probe_escalation, record_probe_timeout, record_suspicion_refuted,
    run_gossip_round, run_probe,
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
fn gossip_round_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = gossip_round_span(1, 42, 3, 10).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn probe_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = probe_span(1, 2, make_addr(3000), "direct").entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn membership_change_span_creates_span() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span = membership_change_span(1, None, NodeStatus::Alive).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn membership_change_span_with_old_status() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span =
            membership_change_span(1, Some(NodeStatus::Alive), NodeStatus::Suspect).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn multiple_spans_count_correctly() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let _span1 = gossip_round_span(1, 1, 2, 5).entered();
        let _span2 = probe_span(1, 2, make_addr(2000), "direct").entered();
        let _span3 = membership_change_span(3, None, NodeStatus::Alive).entered();
        assert_eq!(span_count.load(Ordering::SeqCst), 3);
    });
}

// ── Gossip Event Tests ────────────────────────────────────────────────────────

#[test]
fn record_gossip_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_gossip_sent(2, make_addr(2000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_gossip_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_gossip_received(2, make_addr(2000), 5);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Probe Event Tests ─────────────────────────────────────────────────────────

#[test]
fn record_ping_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_ping_sent(2, make_addr(2000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_ack_received_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_ack_received(2, make_addr(2000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_probe_timeout_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_probe_timeout(2, "direct");
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_probe_escalation_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_probe_escalation(2, 3);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_ping_req_sent_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_ping_req_sent(2, make_addr(2000), make_addr(3000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Membership Event Tests ────────────────────────────────────────────────────

#[test]
fn record_node_joined_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_node_joined(2, make_addr(2000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_node_suspected_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_node_suspected(2);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_node_dead_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_node_dead(2);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_node_rejoined_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_node_rejoined(2, make_addr(2000), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_suspicion_refuted_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_suspicion_refuted(1, 0, 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn record_node_left_emits_event() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_node_left(2, make_addr(2000));
        assert_eq!(event_count.load(Ordering::SeqCst), 1);
    });
}

// ── Instrumented Wrapper Tests ────────────────────────────────────────────────

#[test]
fn run_gossip_round_executes_closure() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let result = run_gossip_round(1, 42, 3, 10, || 123);
        assert_eq!(result, 123);
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn run_probe_executes_closure() {
    let (subscriber, span_count, _) = test_subscriber();
    with_default(subscriber, || {
        let result = run_probe(1, 2, make_addr(2000), "direct", || "success");
        assert_eq!(result, "success");
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
    });
}

// ── Combined Flow Tests ───────────────────────────────────────────────────────

#[test]
fn multiple_events_count_correctly() {
    let (subscriber, _, event_count) = test_subscriber();
    with_default(subscriber, || {
        record_gossip_sent(1, make_addr(1000));
        record_ping_sent(2, make_addr(2000));
        record_ack_received(3, make_addr(3000));
        assert_eq!(event_count.load(Ordering::SeqCst), 3);
    });
}

#[test]
fn gossip_round_with_events() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        let _span = gossip_round_span(1, 1, 3, 10).entered();
        record_gossip_sent(2, make_addr(2000));
        record_gossip_sent(3, make_addr(3000));
        record_gossip_sent(4, make_addr(4000));
        assert_eq!(span_count.load(Ordering::SeqCst), 1);
        assert_eq!(event_count.load(Ordering::SeqCst), 3);
    });
}

#[test]
fn probe_failure_sequence() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        // Direct probe
        let _direct = probe_span(1, 2, make_addr(2000), "direct").entered();
        record_ping_sent(2, make_addr(2000));
        record_probe_timeout(2, "direct");

        // Escalation to indirect
        record_probe_escalation(2, 3);

        // Indirect probe
        let _indirect = probe_span(1, 2, make_addr(2000), "indirect").entered();
        record_ping_req_sent(2, make_addr(2000), make_addr(3000));
        record_probe_timeout(2, "indirect");

        // Node declared dead
        record_node_suspected(2);
        record_node_dead(2);

        assert_eq!(span_count.load(Ordering::SeqCst), 2);
        assert_eq!(event_count.load(Ordering::SeqCst), 7);
    });
}

#[test]
fn membership_lifecycle() {
    let (subscriber, span_count, event_count) = test_subscriber();
    with_default(subscriber, || {
        // Node joins
        let _join = membership_change_span(2, None, NodeStatus::Alive).entered();
        record_node_joined(2, make_addr(2000));

        // Node becomes suspect
        let _suspect =
            membership_change_span(2, Some(NodeStatus::Alive), NodeStatus::Suspect).entered();
        record_node_suspected(2);

        // Node refutes suspicion
        record_suspicion_refuted(2, 0, 1);

        // Node eventually dies
        let _dead =
            membership_change_span(2, Some(NodeStatus::Suspect), NodeStatus::Dead).entered();
        record_node_dead(2);

        assert_eq!(span_count.load(Ordering::SeqCst), 3);
        assert_eq!(event_count.load(Ordering::SeqCst), 4);
    });
}
