//! Integration tests for the RFC 793 persist timer.
//!
//! # What is tested
//!
//! ```text
//!  Client                               Server (recv_buf = 64 B)
//!  ──────                               ──────────────────────────
//!  send(msg0, 40 B) ─────────────────▶  buffer = 40 B  rwnd = 24
//!  send(msg1, 40 B) ─────────────────▶  buffer = 64 B  rwnd = 0
//!                ◀──────────────────── ACK(rwnd = 0)
//!  persist.is_active()  = true
//!  persist probe 1 ─────────────────▶  (dropped / ignored — buffer full)
//!                ◀──────────────────── ACK(rwnd = 0)  [probe elicited ack]
//!  persist probe 2 ──── …
//!                    ⋮
//!                                      server drains msg0 → rwnd = 40
//!                ◀──────────────────── ACK(rwnd = 40)
//!  persist.is_active()  = false
//!  retransmit timer re-armed
//!  send(msg2, 40 B) ─────────────────▶  …
//!  send(msg3, 40 B) ─────────────────▶  …
//! ```
//!
//! # Assertions
//!
//! 1. **All data delivered** — byte-exact equality.
//! 2. **Persist timer fired** — `probe_count > 0` after transfer.
//! 3. **No spurious SR retransmits** — `sr_retransmit_count == 0` on clean
//!    loopback (no packet loss, so the retransmit timer should never fire).
//!
//! The third assertion proves that the timers are orthogonal: the persist
//! timer handled the stall without triggering a CC-penalty retransmit.

use std::net::SocketAddr;
use std::time::Duration;

use tcp_over_udp::{
    connection::ConnError,
    gbn_connection::GbnConnection,
    socket::Socket,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn ephemeral() -> Socket {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Socket::bind(addr).await.expect("bind")
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Verifies the full stall → persist-probe → window-reopens → recovery cycle.
///
/// The server uses a 64-byte receive buffer and deliberately pauses between
/// `recv()` calls (600 ms each) so that the client's send window is blocked
/// by `rwnd == 0` for long enough to observe at least one persist probe.
///
/// On clean loopback there must be zero SR retransmissions: the persist path,
/// not the retransmit path, handles the stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_persist_timer_stall_and_recovery() {
    // ── Parameters ────────────────────────────────────────────────────────────
    const WINDOW:   usize = 4;
    const RECV_BUF: usize = 64;   // tiny server buffer → easy to saturate
    const MSG_SIZE: usize = 40;   // two messages fill the buffer (80 > 64)
    const MSG_COUNT: usize = 4;   // 4 × 40 = 160 bytes total

    // ── Sockets ───────────────────────────────────────────────────────────────
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    // ── Server task ───────────────────────────────────────────────────────────
    //
    // Accepts a connection with a small receive buffer.  After each recv() it
    // sleeps 600 ms, keeping the buffer full and holding rwnd = 0 long enough
    // for the client to send at least one persist probe.
    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept_with_recv_buf(server_sock, WINDOW, RECV_BUF)
            .await
            .expect("server: accept");

        let mut received: Vec<u8> = Vec::new();
        loop {
            match conn.recv().await {
                Ok(data) => {
                    received.extend_from_slice(&data);
                    // Pause to hold the receive buffer full.  This forces the
                    // client's sender into a zero-window stall and triggers
                    // the persist timer.
                    tokio::time::sleep(Duration::from_millis(600)).await;
                }
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server: recv error: {e}"),
            }
        }
        conn.close().await.ok();
        received
    });

    // ── Client task ───────────────────────────────────────────────────────────
    //
    // Sends MSG_COUNT × MSG_SIZE bytes sequentially.  The second send will
    // stall on rwnd == 0; subsequent sends recover as the server drains.
    // After flush(), before close(), we snapshot the persist and retransmit
    // counters for the test assertions.
    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("client: connect");

        let payloads: Vec<Vec<u8>> = (0..MSG_COUNT)
            .map(|i| vec![i as u8; MSG_SIZE])
            .collect();

        for p in &payloads {
            conn.send(p).await.expect("client: send");
        }
        conn.flush().await.expect("client: flush");

        // Capture counters AFTER flush (all data acknowledged) but BEFORE
        // close() so the connection is still accessible.
        let probes      = conn.sender.persist.probe_count();
        let retransmits = conn.sender.sr_retransmit_count();

        conn.close().await.ok();

        (payloads, probes, retransmits)
    });

    // ── Wait ──────────────────────────────────────────────────────────────────
    let test_timeout = Duration::from_secs(30);
    let (srv, cli) =
        tokio::time::timeout(test_timeout, async { tokio::join!(server, client) })
            .await
            .expect("test timed out — possible deadlock or infinite stall");

    let received                = srv.expect("server task panicked");
    let (payloads, probes, retransmits) = cli.expect("client task panicked");

    // ── Assertions ────────────────────────────────────────────────────────────

    // 1. Data integrity: all bytes delivered, in order, without corruption.
    let expected: Vec<u8> = payloads.into_iter().flatten().collect();
    assert_eq!(
        received.len(),
        expected.len(),
        "byte count mismatch: got {} expected {}",
        received.len(),
        expected.len()
    );
    assert_eq!(received, expected, "data corruption detected");

    // 2. Persist timer must have fired at least once during the stall.
    assert!(
        probes > 0,
        "persist timer never fired — zero-window stall was not handled by persist path \
         (probes={probes}, retransmits={retransmits})"
    );

    // 3. No spurious SR retransmits on clean loopback.
    //    The persist path probes WITHOUT calling retransmit_oldest(), so
    //    sr_retransmit_count must stay at 0 when there is no packet loss.
    assert_eq!(
        retransmits,
        0,
        "spurious SR retransmit detected during zero-window stall \
         (probes={probes}, retransmits={retransmits})"
    );

    println!(
        "\n  persist probes fired : {probes}\n  SR retransmits       : {retransmits}\n  bytes received       : {}/{}\n",
        received.len(), expected.len()
    );
}
