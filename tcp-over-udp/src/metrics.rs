//! TCP state-machine metrics with a Prometheus-compatible HTTP endpoint.
//!
//! Five counters/gauges exposed:
//!
//! | Metric | Type | Description |
//! |---|---|---|
//! | `tcp_connections_active` | Gauge | Currently open connections |
//! | `tcp_connections_time_wait` | Gauge | Connections in TIME_WAIT |
//! | `tcp_retransmissions_total` | Counter | Total segment retransmissions |
//! | `tcp_duplicate_acks` | Counter | Total duplicate ACKs received |
//! | `tcp_rto_events` | Counter | Total RTO back-off events |
//!
//! # Usage
//!
//! ```ignore
//! // Start the Prometheus endpoint on port 9100:
//! tcp_over_udp::metrics::start_server(9100);
//!
//! // Instrument code:
//! tcp_over_udp::metrics::ACTIVE_CONNECTIONS.inc();
//! tcp_over_udp::metrics::ACTIVE_CONNECTIONS.dec();
//! tcp_over_udp::metrics::RETRANSMISSIONS.inc();
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Atomic gauge / counter primitives
// ---------------------------------------------------------------------------

/// Monotonically increasing counter.
pub struct Counter(AtomicU64);

impl Counter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Increment by 1.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Gauge that can go up and down.
pub struct Gauge(AtomicU64);

impl Gauge {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Increment by 1.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement by 1 (saturating).
    pub fn dec(&self) {
        // Saturating subtract via CAS loop.
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v > 0 { Some(v - 1) } else { None }
            });
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Global metrics
// ---------------------------------------------------------------------------

/// Currently open (Established) connections.
pub static ACTIVE_CONNECTIONS: Gauge = Gauge::new();

/// Connections currently in TIME_WAIT state.
pub static TIME_WAIT_CONNECTIONS: Gauge = Gauge::new();

/// Total segment retransmissions.
pub static RETRANSMISSIONS: Counter = Counter::new();

/// Total duplicate ACKs received.
pub static DUPLICATE_ACKS: Counter = Counter::new();

/// Total RTO back-off events.
pub static RTO_EVENTS: Counter = Counter::new();

// ---------------------------------------------------------------------------
// Prometheus text exposition
// ---------------------------------------------------------------------------

/// Render all metrics in Prometheus text exposition format.
pub fn render_prometheus() -> String {
    let mut out = String::with_capacity(512);

    out.push_str("# HELP tcp_connections_active Currently open TCP connections.\n");
    out.push_str("# TYPE tcp_connections_active gauge\n");
    out.push_str(&format!(
        "tcp_connections_active {}\n",
        ACTIVE_CONNECTIONS.get()
    ));

    out.push_str("# HELP tcp_connections_time_wait Connections in TIME_WAIT state.\n");
    out.push_str("# TYPE tcp_connections_time_wait gauge\n");
    out.push_str(&format!(
        "tcp_connections_time_wait {}\n",
        TIME_WAIT_CONNECTIONS.get()
    ));

    out.push_str("# HELP tcp_retransmissions_total Total segment retransmissions.\n");
    out.push_str("# TYPE tcp_retransmissions_total counter\n");
    out.push_str(&format!(
        "tcp_retransmissions_total {}\n",
        RETRANSMISSIONS.get()
    ));

    out.push_str("# HELP tcp_duplicate_acks Total duplicate ACKs received.\n");
    out.push_str("# TYPE tcp_duplicate_acks counter\n");
    out.push_str(&format!("tcp_duplicate_acks {}\n", DUPLICATE_ACKS.get()));

    out.push_str("# HELP tcp_rto_events Total RTO back-off events.\n");
    out.push_str("# TYPE tcp_rto_events counter\n");
    out.push_str(&format!("tcp_rto_events {}\n", RTO_EVENTS.get()));

    out
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

/// Spawn a minimal HTTP server on `port` that serves `/metrics`.
///
/// Runs as a background tokio task; returns immediately.
/// Binds to `0.0.0.0:<port>`.  If the port is 0 the OS picks one and the
/// actual address is logged.
pub fn start_server(port: u16) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(format!("0.0.0.0:{port}")).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("[metrics] failed to bind port {port}: {e}");
                return;
            }
        };
        let local = listener.local_addr().unwrap();
        log::info!("[metrics] Prometheus endpoint at http://{local}/metrics");

        loop {
            let (mut stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("[metrics] accept error: {e}");
                    continue;
                }
            };

            tokio::spawn(async move {
                // Read (and discard) the HTTP request.
                let mut buf = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let body = render_prometheus();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let c = Counter::new();
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc();
        assert_eq!(c.get(), 2);
    }

    #[test]
    fn gauge_inc_dec() {
        let g = Gauge::new();
        g.inc();
        g.inc();
        assert_eq!(g.get(), 2);
        g.dec();
        assert_eq!(g.get(), 1);
        g.dec();
        assert_eq!(g.get(), 0);
        // Saturating: dec at 0 stays 0.
        g.dec();
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn prometheus_output_contains_all_metrics() {
        let text = render_prometheus();
        assert!(text.contains("tcp_connections_active"));
        assert!(text.contains("tcp_connections_time_wait"));
        assert!(text.contains("tcp_retransmissions_total"));
        assert!(text.contains("tcp_duplicate_acks"));
        assert!(text.contains("tcp_rto_events"));
    }
}
