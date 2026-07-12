//! Integration tests for RST (reset) packet generation and handling.
//!
//! Validates the acceptance criteria from issue #14:
//!
//! 1. **Unexpected SYN in Established state** — a bare SYN arriving in a
//!    synchronised state triggers RST (half-open detection, RFC 793 §3.4).
//! 2. **Sequence number validation errors** — a data segment whose seq is
//!    wildly outside the receive window triggers RST.
//! 3. **Abort path testing** — calling `abort()` sends RST to the peer and
//!    transitions to Closed.
//! 4. **RST does not conflict with normal teardown** — a clean send/recv
//!    exchange followed by graceful close still works.

use std::time::Duration;

use tcp_over_udp::{
    connection::{ConnError, Connection},
    gbn_connection::GbnConnection,
    packet::{flags, Header, Packet},
    socket::Socket,
};

/// Bind a socket to an OS-assigned loopback port.
async fn ephemeral() -> Socket {
    let addr = "127.0.0.1:0".parse().unwrap();
    Socket::bind(addr).await.expect("bind failed")
}

// ---------------------------------------------------------------------------
// Test 1: Unexpected SYN in Established state triggers RST
// ---------------------------------------------------------------------------

/// When an established connection receives a bare SYN, it should respond
/// with RST and transition to Closed (half-open detection, RFC 793 §3.4).
///
/// The client completes the handshake, then decomposes its Connection to
/// get the raw socket and manually sends a SYN from the peer address.
#[tokio::test]
async fn test_rst_on_unexpected_syn_in_established() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");

        // The recv() call should see the injected SYN, send RST, and return Reset.
        let result = conn.recv().await;
        assert!(
            matches!(result, Err(ConnError::Reset)),
            "expected ConnError::Reset on unexpected SYN, got {result:?}"
        );
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        // Complete the handshake, then decompose to get the raw socket.
        let conn = Connection::connect(sock, server_addr).await.expect("connect");
        let (_state, socket, peer, _next_seq, _rcv_nxt, _rto, _mss, _, _) = conn.into_parts();

        // Send a bare SYN from the client's address — the server will see it
        // as coming from its known peer.
        let syn = Packet {
            header: Header {
                seq: 999,
                ack: 0,
                flags: flags::SYN,
                window: 8192,
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        };
        socket.send_to(&syn, peer).await.expect("inject SYN");

        // Give the server time to process.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 2: Implausible sequence number triggers RST
// ---------------------------------------------------------------------------

/// A data segment whose seq is wildly different from rcv_nxt should trigger
/// RST, not a dup-ACK.  This guards against stale/spoofed connections.
///
/// The client decomposes its Connection to get the raw socket and sends a
/// data segment with an implausible sequence number.
#[tokio::test]
async fn test_rst_on_implausible_seq() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");

        // recv() should see the implausible-seq packet, send RST, return Reset.
        let result = conn.recv().await;
        assert!(
            matches!(result, Err(ConnError::Reset)),
            "expected ConnError::Reset on implausible seq, got {result:?}"
        );
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = Connection::connect(sock, server_addr).await.expect("connect");
        let (_state, socket, peer, _next_seq, _rcv_nxt, _rto, _mss, _, _) = conn.into_parts();

        // Send a data segment with a wildly wrong sequence number from the
        // client's address.  The server's rcv_nxt is near the client's ISN+1;
        // seq = u32::MAX / 2 is far outside any plausible window.
        let bad_pkt = Packet {
            header: Header {
                seq: u32::MAX / 2,
                ack: 0,
                flags: flags::ACK,
                window: 8192,
                checksum: 0,
            },
            options: vec![],
            payload: b"stale data from another connection".to_vec(),
        };
        socket.send_to(&bad_pkt, peer).await.expect("inject bad-seq");

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 3: abort() sends RST and transitions to Closed
// ---------------------------------------------------------------------------

/// Calling `abort()` on one side should send RST, making the peer's next
/// operation return `ConnError::Reset`.
#[tokio::test]
async fn test_abort_sends_rst() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");

        // The server's recv() should see the RST sent by the client's abort().
        let result = conn.recv().await;
        assert!(
            matches!(result, Err(ConnError::Reset)),
            "expected ConnError::Reset after peer abort, got {result:?}"
        );
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("connect");

        // Abort immediately — no graceful close.
        conn.abort().await.expect("abort");

        // After abort, state must be Closed.
        assert_eq!(conn.state, tcp_over_udp::state::ConnectionState::Closed);
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 4: abort() on stop-and-wait Connection
// ---------------------------------------------------------------------------

/// Verifies that the abort path also works on the lower-level `Connection`.
#[tokio::test]
async fn test_connection_abort_sends_rst() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = Connection::accept(server_sock).await.expect("accept");

        let result = conn.recv().await;
        assert!(
            matches!(result, Err(ConnError::Reset)),
            "expected ConnError::Reset after peer abort, got {result:?}"
        );
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = Connection::connect(sock, server_addr).await.expect("connect");

        conn.abort().await.expect("abort");
        assert_eq!(conn.state, tcp_over_udp::state::ConnectionState::Closed);
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 5: RST does not break normal teardown
// ---------------------------------------------------------------------------

/// A clean send → recv → close sequence must still work correctly.
/// This ensures the RST checks do not trigger false positives.
#[tokio::test]
async fn test_normal_teardown_unaffected() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");

        let data = conn.recv().await.expect("recv");
        assert_eq!(data, b"ping");

        conn.send(b"pong").await.expect("send");
        conn.close().await.expect("close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("connect");

        conn.send(b"ping").await.expect("send");

        let reply = conn.recv().await.expect("recv");
        assert_eq!(reply, b"pong");

        conn.close().await.expect("close");
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 6: RST received during send/flush path (process_incoming)
// ---------------------------------------------------------------------------

/// When the sender is blocked in flush() waiting for ACKs, an incoming RST
/// should immediately unblock it with ConnError::Reset.
#[tokio::test]
async fn test_rst_received_during_flush() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");

        // Receive one message, then abort — the client is still flushing.
        let _ = conn.recv().await;
        conn.abort().await.expect("abort");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("connect");

        // Send several messages; the server will abort mid-stream.
        for i in 0..8u32 {
            let msg = format!("msg-{i}");
            match conn.send(msg.as_bytes()).await {
                Ok(()) => {}
                Err(ConnError::Reset) => return, // expected
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // If sends all succeeded, flush should catch the RST.
        match conn.flush().await {
            Err(ConnError::Reset) => {} // expected
            other => panic!("expected Reset during flush, got {other:?}"),
        }
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 7: abort on already-closed connection is a no-op
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_abort_on_closed_is_noop() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 1)
            .await
            .expect("accept");
        let _ = conn.recv().await;
        conn.close().await.expect("close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, 1)
            .await
            .expect("connect");

        conn.send(b"x").await.expect("send");
        conn.close().await.expect("close");

        // Second abort after close should be a no-op.
        conn.abort().await.expect("abort on closed");
        assert_eq!(conn.state, tcp_over_udp::state::ConnectionState::Closed);
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}
