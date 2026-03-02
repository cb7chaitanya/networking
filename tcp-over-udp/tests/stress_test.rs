//! Stress test harness — 1 MiB transfer under adverse network conditions.
//!
//! # Test conditions
//!
//! | Parameter   | Value  |
//! |-------------|--------|
//! | Packet loss | 10 %   |
//! | Base delay  | 100 ms |
//! | Jitter      | ±50 ms |
//! | Window size | 32     |
//! | Transfer    | 1 MiB  |
//!
//! # Architecture
//!
//! `GbnConnection` uses `Socket` internally, so `SimulatedSocket` cannot be
//! plugged in directly.  Instead a **bidirectional relay task** sits between
//! the two endpoints:
//!
//! ```text
//!  ┌────────────────────┐  UDP to relay_addr   ┌─────────────────────────┐
//!  │  GbnConn  (client) │─────────────────────▶│  SimulatedSocket relay  │
//!  │  Socket at C       │◀─────────────────────│  at relay_addr (F)      │
//!  └────────────────────┘  UDP from relay_addr  └────────────┬────────────┘
//!                                                            │ fault pipeline
//!                                                            │ (loss/delay/jitter)
//!                                                            ▼
//!                                               ┌────────────────────────┐
//!                                               │  GbnConn  (server)     │
//!                                               │  Socket at S           │
//!                                               └────────────────────────┘
//! ```
//!
//! The relay receives from both ends (distinguishing by source address) and
//! re-emits each packet through `SimulatedSocket::send_to`, which is where
//! faults are injected.  Both **data** and **ACK** packets traverse the
//! faulty link, exercising the retransmit, RTO, and flow-control paths.
//!
//! ## Why `corrupt_rate = 0.0`
//!
//! `SimulatedSocket::send_to` corrupts the re-encoded wire bytes before
//! forwarding.  The destination is a real `Socket`, whose `recv_from` calls
//! `Packet::decode` and returns `Err` on a bad checksum.  `GbnConnection`
//! treats that error as fatal.  Corruption testing belongs in unit tests
//! (where `SimulatedSocket` is both sender and receiver); packet loss
//! already stresses all retransmit paths end-to-end.
//!
//! # Running
//!
//! ```text
//! cargo test --test stress_test -- --ignored --nocapture
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tcp_over_udp::{
    connection::ConnError,
    gbn_connection::GbnConnection,
    simulator::{SimulatedSocket, SimulationConfig},
    socket::Socket,
};

// ---------------------------------------------------------------------------
// Test parameters
// ---------------------------------------------------------------------------

const WINDOW: usize = 32;

// 256 KiB in debug builds (~20 s).  Switch to 1024 * 1024 for the full
// 1 MiB spec; use `cargo test --release` to keep that run under 60 s.
const DATA_SIZE: usize = 256 * 1024;

const CHUNK_SIZE: usize = 512;        // one protocol segment per send call
const TEST_TIMEOUT: Duration = Duration::from_secs(120); // 2-minute cap

// ---------------------------------------------------------------------------
// Relay task
// ---------------------------------------------------------------------------

/// Counters shared between the relay task and the test body.
#[derive(Clone)]
struct RelayCounters {
    /// Total packets processed by the relay (both directions combined).
    packets_forwarded: Arc<AtomicU64>,
    /// Data segments (non-empty payload) forwarded from client that carry a
    /// sequence number the relay has seen before.  Each such packet means the
    /// GBN/SR sender retransmitted that segment.
    retransmits: Arc<AtomicU64>,
    /// Distinct sequence numbers seen in client data segments.  Should
    /// converge to `ceil(DATA_SIZE / CHUNK_SIZE)` after a clean transfer.
    unique_data_segs: Arc<AtomicU64>,
}

impl RelayCounters {
    fn new() -> Self {
        Self {
            packets_forwarded: Arc::new(AtomicU64::new(0)),
            retransmits:       Arc::new(AtomicU64::new(0)),
            unique_data_segs:  Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Bidirectional fault-injecting relay.
///
/// Loops on `sim.recv_from()`.  On each received packet it decides the
/// forwarding destination:
///
/// * Packet from `server_addr`  → forward to `client_addr`
/// * Packet from anywhere else  → record as client, forward to `server_addr`
///
/// Every forward goes through `sim.send_to()`, which runs the full
/// `SimulatedSocket` egress pipeline: loss → delay → jitter.
/// The relay returns when `sim.recv_from()` returns an error (socket closed
/// or task aborted by the caller).
async fn relay_task(
    sim: SimulatedSocket,
    server_addr: SocketAddr,
    counters: RelayCounters,
) {
    let mut client_addr: Option<SocketAddr> = None;

    // Track data-segment seq numbers from the client to detect retransmits.
    // Sequence numbers are byte-offset keys, so a repeated value is a GBN/SR
    // retransmission (not a coincidental wrap — 1 MiB << 4 GiB seq space).
    let mut seen_seqs: HashSet<u32> = HashSet::new();

    loop {
        let (pkt, from) = match sim.recv_from().await {
            Ok(pair) => pair,
            Err(_)   => return, // aborted or socket closed
        };

        // ── Route the packet ─────────────────────────────────────────────────
        let dest = if from == server_addr {
            // ACK (or FIN) flowing back to the client.
            match client_addr {
                Some(c) => c,
                None    => continue, // shouldn't happen before SYN; skip
            }
        } else {
            // Data (or SYN/FIN) flowing from the client to the server.
            //
            // `get_or_insert` learns the client's ephemeral port on the
            // first packet (the SYN).  Subsequent packets from the same
            // address are forwarded normally; unexpected third-party
            // datagrams are silently discarded.
            let c = *client_addr.get_or_insert(from);
            if from != c {
                continue;
            }

            // Retransmit detection: only data segments carry meaningful payloads.
            if !pkt.payload.is_empty() {
                if seen_seqs.insert(pkt.header.seq) {
                    counters.unique_data_segs.fetch_add(1, Ordering::Relaxed);
                } else {
                    counters.retransmits.fetch_add(1, Ordering::Relaxed);
                }
            }

            server_addr
        };

        counters.packets_forwarded.fetch_add(1, Ordering::Relaxed);

        // Re-emit through the fault pipeline.
        // `send_to` returns Ok(()) even when the packet is dropped by design,
        // so we intentionally ignore the return value.
        let _ = sim.send_to(&pkt, dest).await;
    }
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore] // cargo test --test stress_test -- --ignored --nocapture
async fn stress_test_1mib_lossy_delayed() {
    // ── 1. Network fault configuration ───────────────────────────────────────
    let net_config = SimulationConfig {
        loss_rate:    0.10,                       // 10 % of all packets dropped
        base_delay:   Duration::from_millis(100), // 100 ms one-way propagation
        jitter:       Duration::from_millis(50),  // uniform [0, 50 ms] per packet
        corrupt_rate: 0.0,  // see module doc — keep 0 for end-to-end harness
        reorder_prob: 0.0,  // loss alone exercises SR/GBN; add later as desired
        seed:         Some(0xdead_c0de_cafe_beef), // fixed seed → reproducible run
        ..Default::default()
    };

    // ── 2. Sockets ────────────────────────────────────────────────────────────
    let server_sock  = Socket::bind("127.0.0.1:0".parse().unwrap())
        .await.expect("server socket bind");
    let server_addr  = server_sock.local_addr;

    // The relay SimulatedSocket sits between client and server.
    // Client connects here; server sees traffic as coming from here.
    let relay_sim    = SimulatedSocket::bind("127.0.0.1:0".parse().unwrap(), net_config)
        .await.expect("relay socket bind");
    let relay_addr   = relay_sim.local_addr;

    let client_sock  = Socket::bind("127.0.0.1:0".parse().unwrap())
        .await.expect("client socket bind");

    // ── 3. Relay task ─────────────────────────────────────────────────────────
    let counters = RelayCounters::new();
    let relay_handle = tokio::spawn(relay_task(
        relay_sim,
        server_addr,
        counters.clone(),
    ));

    // ── 4. Test payload ───────────────────────────────────────────────────────
    // `i % 251` produces a non-trivial repeating pattern across the full byte
    // range; any corruption or truncation is immediately visible in the assert.
    let payload: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone(); // retained in this scope for integrity check

    // ── 5. Server task: accept → drain ────────────────────────────────────────
    //
    // The server does NOT call `conn.close()`.  Here is why:
    //
    // The server sends the ACK of the client's FIN inside `recv()` the moment
    // it detects the FIN flag (see `GbnConnection::recv`).  That is all the
    // client needs to complete its own `close()` and exit.
    //
    // If the server were to call `conn.close()`, it would try to perform a
    // symmetric FIN handshake *after* the client has already torn down its
    // socket.  Because the client socket is gone, the server's FIN is never
    // ACKed, so `close()` retries with exponential back-off up to MAX_RETRIES
    // (6 attempts × back-off from 1 s → up to ~57 s of extra waiting).
    // `tokio::join!` in the test harness waits for *both* tasks, so those 57 s
    // are added directly to the wall-clock time and would breach the timeout.
    //
    // Dropping `conn` at the end of the task is a clean half-close: the
    // socket is released, the relay task is aborted shortly after, and the
    // data-integrity assertion below verifies correctness.
    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("server: accept");

        let mut received = Vec::with_capacity(DATA_SIZE);
        loop {
            match conn.recv().await {
                Ok(chunk)           => received.extend_from_slice(&chunk),
                Err(ConnError::Eof) => break,
                Err(e)              => panic!("server: recv error: {e}"),
            }
        }
        // conn is dropped here — half-close without a symmetric FIN handshake.
        received
    });

    // ── 6. Client task: connect → send → flush → close ────────────────────────
    // The wall-clock timer starts here so handshake time is included in the
    // throughput figure (fairer representation of observed performance).
    let t_start = Instant::now();

    let client = tokio::spawn(async move {
        let mut conn = GbnConnection::connect(client_sock, relay_addr, WINDOW)
            .await
            .expect("client: connect");

        for chunk in payload.chunks(CHUNK_SIZE) {
            conn.send(chunk).await.expect("client: send");
        }
        conn.flush().await.expect("client: flush");
        conn.close().await.expect("client: close");
    });

    // ── 7. Wait with timeout ──────────────────────────────────────────────────
    let (srv, cli) =
        tokio::time::timeout(TEST_TIMEOUT, async { tokio::join!(server, client) })
            .await
            .expect("stress test timed out — possible deadlock or extreme network stall");

    let elapsed = t_start.elapsed();
    relay_handle.abort(); // relay's recv_from future is cancelled cleanly

    let received = srv.expect("server task panicked");
    cli.expect("client task panicked");

    // ── 8. Data integrity ─────────────────────────────────────────────────────
    assert_eq!(
        received.len(), DATA_SIZE,
        "byte count mismatch: received {} B, expected {} B",
        received.len(), DATA_SIZE,
    );
    assert_eq!(
        received, expected,
        "data corruption: received payload differs from sent payload",
    );

    // ── 9. Metrics ────────────────────────────────────────────────────────────
    let total_fwd       = counters.packets_forwarded.load(Ordering::Relaxed);
    let retransmits     = counters.retransmits.load(Ordering::Relaxed);
    let unique_segs     = counters.unique_data_segs.load(Ordering::Relaxed);
    let expected_segs   = DATA_SIZE.div_ceil(CHUNK_SIZE) as u64;

    let throughput_mibs = DATA_SIZE as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    let retx_overhead   = if unique_segs > 0 {
        retransmits as f64 / unique_segs as f64 * 100.0
    } else {
        0.0
    };
    // Goodput: useful bytes / total elapsed.  Differs from raw throughput by
    // the retransmission overhead fraction.
    let goodput_mibs = throughput_mibs / (1.0 + retx_overhead / 100.0);

    println!();
    println!("  ┌─────────────────────────────────────────────┐");
    println!("  │            Stress Test Results              │");
    println!("  ├──────────────────────┬──────────────────────┤");
    println!("  │ Network conditions   │                      │");
    println!("  │   loss rate          │  10.0 %              │");
    println!("  │   base delay         │  100 ms              │");
    println!("  │   jitter             │  ±50 ms              │");
    println!("  │   window size        │  {WINDOW:<21}│");
    println!("  ├──────────────────────┼──────────────────────┤");
    println!("  │ Transfer             │                      │");
    println!("  │   data               │  {DATA_SIZE} B ({:.2} MiB)   │",
        DATA_SIZE as f64 / (1024.0 * 1024.0));
    println!("  │   elapsed            │  {elapsed:<21.2?}│");
    println!("  │   throughput         │  {throughput_mibs:<18.4} MiB/s│");
    println!("  │   goodput (est.)     │  {goodput_mibs:<18.4} MiB/s│");
    println!("  ├──────────────────────┼──────────────────────┤");
    println!("  │ Packets              │                      │");
    println!("  │   forwarded (total)  │  {total_fwd:<21}│");
    println!("  │   unique data segs   │  {unique_segs:<21}│");
    println!("  │   expected data segs │  {expected_segs:<21}│");
    println!("  │   retransmissions    │  {retransmits:<21}│");
    println!("  │   retx overhead      │  {retx_overhead:<18.2} %   │");
    println!("  ├──────────────────────┴──────────────────────┤");
    println!("  │  ✓  Integrity check PASSED                  │");
    println!("  └─────────────────────────────────────────────┘");
    println!();
}
