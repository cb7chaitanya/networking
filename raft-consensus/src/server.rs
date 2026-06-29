//! Minimal HTTP server exposing Raft metrics.
//!
//! A background thread accepts TCP connections and dispatches three routes:
//!
//! | Path       | Content-Type                        | Body                                |
//! |------------|-------------------------------------|-------------------------------------|
//! | `/metrics` | `text/plain; version=0.0.4`         | Prometheus text exposition format   |
//! | `/healthz` | `application/json`                  | `{"status":"ok"}`                   |
//! | `/raft`    | `application/json`                  | All metrics as a JSON object        |
//!
//! All other paths return `404 Not Found`.
//!
//! The server uses HTTP/1.0 semantics (one response per connection, then close)
//! so no keep-alive or chunked-encoding complexity is needed.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use raft_consensus::metrics::RaftMetrics;
//! use raft_consensus::server::MetricsServer;
//!
//! let metrics = Arc::new(RaftMetrics::new());
//! // Pass "127.0.0.1:0" to let the OS pick a free port.
//! let addr = MetricsServer::spawn("127.0.0.1:9090", Arc::clone(&metrics)).unwrap();
//! println!("metrics at http://{addr}/metrics");
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use crate::metrics::RaftMetrics;

// ── MetricsServer ──

/// HTTP server that exposes Raft metrics on three endpoints.
///
/// Runs on a dedicated background thread; the main Raft loop is unaffected.
pub struct MetricsServer;

impl MetricsServer {
    /// Bind `addr` and spawn a background thread to serve connections.
    ///
    /// Passing port `0` lets the OS assign a free port; the returned string is
    /// the actual bound address (e.g., `"127.0.0.1:54321"`).
    ///
    /// The server runs until the process exits; there is no graceful shutdown
    /// in this implementation.
    pub fn spawn(addr: &str, metrics: Arc<RaftMetrics>) -> std::io::Result<String> {
        let listener = TcpListener::bind(addr)?;
        // Retrieve the actual address before moving the listener.
        let bound = listener.local_addr()?.to_string();

        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(conn) => {
                        let m = Arc::clone(&metrics);
                        thread::spawn(move || handle_connection(conn, &m));
                    }
                    Err(_) => break, // listener closed or OS error — stop accepting
                }
            }
        });

        Ok(bound)
    }
}

// ── Connection handler ──

fn handle_connection(stream: TcpStream, metrics: &RaftMetrics) {
    // We need to both read (BufReader) and write to the same TcpStream.
    // Clone the stream so the writer can share the underlying fd.
    let writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };

    let mut reader = BufReader::new(&stream);

    // ── Parse the request line ──
    // Example: "GET /metrics HTTP/1.1\r\n"
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();

    // ── Drain remaining headers so the socket is clean ──
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            _ => {}
        }
    }

    // ── Build the response ──
    let (status, content_type, body) = route(&path, metrics);

    write_response(writer, status, content_type, &body);
}

// ── Router ──

fn route<'a>(path: &str, metrics: &RaftMetrics) -> (&'a str, &'a str, String) {
    match path {
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            metrics.render_prometheus(),
        ),
        "/healthz" => (
            "200 OK",
            "application/json",
            r#"{"status":"ok"}"#.to_string(),
        ),
        "/raft" => (
            "200 OK",
            "application/json",
            metrics.render_json(),
        ),
        _ => (
            "404 Not Found",
            "text/plain",
            "Not Found\n".to_string(),
        ),
    }
}

// ── Response writer ──

fn write_response(mut w: TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.0 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    let _ = w.write_all(response.as_bytes());
}
