//! Integration tests for the 3-way handshake.
//!
//! Each test spins up a real `tokio::net::UdpSocket` on loopback, runs the
//! server half in a background task, and verifies that both sides reach
//! `ConnectionState::Established`.

use std::net::SocketAddr;
use std::time::Duration;

use tcp_over_udp::{
    connection::{ConnError, Connection},
    socket::Socket,
    state::ConnectionState,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Bind a server socket on an OS-chosen loopback port and return
/// `(socket, resolved_addr)` so the client knows where to connect.
async fn bind_server() -> (Socket, SocketAddr) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket = Socket::bind(addr).await.expect("bind server socket");
    let local = socket.local_addr;
    (socket, local)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Both sides should reach `Established` after a clean handshake on loopback.
#[tokio::test]
async fn handshake_both_sides_reach_established() {
    let (server_socket, server_addr) = bind_server().await;

    // Server runs in a background task; it blocks on `accept` until the SYN arrives.
    let server_task =
        tokio::spawn(async move { Connection::accept(server_socket).await });

    // Client connects from an ephemeral port.
    let client_socket = Socket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind client socket");
    let client_conn = tokio::time::timeout(
        Duration::from_secs(5),
        Connection::connect(client_socket, server_addr),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect failed");

    let server_conn = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server accept timed out")
        .expect("server task panicked")
        .expect("server accept failed");

    assert_eq!(client_conn.state, ConnectionState::Established);
    assert_eq!(server_conn.state, ConnectionState::Established);
}

/// After the handshake the client's `sender.next_seq` must equal `ISN + 1`
/// and the server's `receiver.rcv_nxt` must match.
#[tokio::test]
async fn handshake_sequence_numbers_agree() {
    let (server_socket, server_addr) = bind_server().await;

    let server_task = tokio::spawn(async move { Connection::accept(server_socket).await });

    let client_socket = Socket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        Connection::connect(client_socket, server_addr),
    )
    .await
    .unwrap()
    .unwrap();

    let server = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // The server's RCV.NXT must equal the client's SND.NXT:
    // both are ISN_client + 1 (SYN consumed one sequence number).
    assert_eq!(
        server.receiver.rcv_nxt,
        client.sender.next_seq,
        "server RCV.NXT should equal client SND.NXT after handshake"
    );

    // Symmetrically for the other direction.
    assert_eq!(
        client.receiver.rcv_nxt,
        server.sender.next_seq,
        "client RCV.NXT should equal server SND.NXT after handshake"
    );
}

/// Connecting to an address where nobody is listening should eventually fail
/// rather than hang forever.
#[tokio::test]
async fn connect_to_silent_peer_fails_with_max_retries() {
    // Port 1 is reserved and will never respond on loopback.
    // We use port 0 binding on a socket we immediately drop so the port is
    // unbound; any SYN sent there will receive no reply.
    let silent_addr: SocketAddr = {
        let tmp = Socket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        tmp.local_addr // ephemeral port; tmp is dropped here (socket closes)
    };

    let client_socket = Socket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();

    let result = Connection::connect(client_socket, silent_addr).await;

    assert!(
        matches!(result, Err(ConnError::HandshakeFailed)),
        "expected HandshakeFailed, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Window Scale Tests
// ---------------------------------------------------------------------------

/// Both sides should negotiate window scaling during handshake.
#[tokio::test]
async fn handshake_negotiates_window_scale() {
    let (server_socket, server_addr) = bind_server().await;

    let server_task =
        tokio::spawn(async move { Connection::accept(server_socket).await });

    let client_socket = Socket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind client socket");
    let client_conn = tokio::time::timeout(
        Duration::from_secs(5),
        Connection::connect(client_socket, server_addr),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect failed");

    let server_conn = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server accept timed out")
        .expect("server task panicked")
        .expect("server accept failed");

    // Both sides should have negotiated window scaling.
    // DEFAULT_WINDOW_SCALE is 7, so both should use scale factor 7.
    assert!(
        client_conn.snd_wscale().is_some(),
        "client should have negotiated snd_wscale"
    );
    assert!(
        client_conn.rcv_wscale().is_some(),
        "client should have negotiated rcv_wscale"
    );
    assert!(
        server_conn.snd_wscale().is_some(),
        "server should have negotiated snd_wscale"
    );
    assert!(
        server_conn.rcv_wscale().is_some(),
        "server should have negotiated rcv_wscale"
    );

    // The scale factors should be reasonable (typically 7 for DEFAULT_WINDOW_SCALE).
    let client_snd = client_conn.snd_wscale().unwrap();
    let client_rcv = client_conn.rcv_wscale().unwrap();
    let server_snd = server_conn.snd_wscale().unwrap();
    let server_rcv = server_conn.rcv_wscale().unwrap();

    // Both sides advertise the same scale factor (DEFAULT_WINDOW_SCALE = 7).
    assert_eq!(client_snd, server_snd, "both sides should use the same snd_wscale");
    assert_eq!(client_rcv, server_rcv, "both sides should use the same rcv_wscale");

    // Scale factors should be within valid TCP range (0-14).
    assert!(client_snd <= 14, "snd_wscale must be <= 14");
    assert!(client_rcv <= 14, "rcv_wscale must be <= 14");
}
