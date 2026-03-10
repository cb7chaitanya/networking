//! Integration tests for the Go-Back-N sliding-window layer.
//!
//! Each test spins up two in-process GBN endpoints talking over the loopback
//! interface.  Both sides are spawned as separate tokio tasks so they can make
//! progress concurrently without blocking each other.

use tcp_over_udp::{
    connection::{ConnError, Connection},
    gbn_connection::GbnConnection,
    packet::DEFAULT_MSS,
    socket::Socket,
};

/// Bind a socket to an OS-assigned port on loopback and return it together
/// with its resolved local address.
async fn ephemeral() -> Socket {
    let addr = "127.0.0.1:0".parse().unwrap();
    Socket::bind(addr).await.expect("bind failed")
}

// ---------------------------------------------------------------------------
// Test 1: basic ping-pong via GBN (window = 1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gbn_basic_send_recv() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 1)
            .await
            .expect("accept");

        let data = conn.recv().await.expect("server recv");
        assert_eq!(data, b"Ping!");

        conn.send(b"Pong!").await.expect("server send");
        conn.close().await.expect("server close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, 1)
            .await
            .expect("connect");

        conn.send(b"Ping!").await.expect("client send");

        let reply = conn.recv().await.expect("client recv");
        assert_eq!(reply, b"Pong!");

        conn.close().await.expect("client close");
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 2: pipelined sends with window > 1
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gbn_pipeline_window4() {
    const WINDOW: usize = 4;
    const MSG_COUNT: usize = 10;

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");

        let mut received: Vec<Vec<u8>> = Vec::new();
        loop {
            match conn.recv().await {
                Ok(data) => received.push(data),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv error: {e}"),
            }
            if received.len() == MSG_COUNT {
                break;
            }
        }
        conn.close().await.expect("server close");
        received
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        for i in 0..MSG_COUNT {
            let msg = format!("msg-{i:02}");
            conn.send(msg.as_bytes()).await.expect("send");
        }
        conn.flush().await.expect("flush");
        conn.close().await.expect("client close");
    });

    let (sr, cr) = tokio::join!(server, client);
    let received = sr.unwrap();
    cr.unwrap();

    assert_eq!(received.len(), MSG_COUNT);
    for (i, chunk) in received.iter().enumerate() {
        let expected = format!("msg-{i:02}");
        assert_eq!(chunk, expected.as_bytes(), "message {i} corrupted");
    }
}

// ---------------------------------------------------------------------------
// Test 3: from_connection — upgrade stop-and-wait to GBN mid-stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gbn_from_connection() {
    use tcp_over_udp::connection::Connection;

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        // Complete handshake with the existing Connection API, then upgrade.
        let conn = Connection::accept(server_sock).await.expect("accept");
        let mut gbn = GbnConnection::from_connection(conn, 4);

        let data = gbn.recv().await.expect("recv");
        assert_eq!(data, b"hello from gbn");

        gbn.send(b"ack from gbn").await.expect("send");
        gbn.close().await.expect("close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = Connection::connect(sock, server_addr).await.expect("connect");
        let mut gbn = GbnConnection::from_connection(conn, 4);

        gbn.send(b"hello from gbn").await.expect("send");

        let reply = gbn.recv().await.expect("recv");
        assert_eq!(reply, b"ack from gbn");

        gbn.close().await.expect("close");
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 4: concurrent session via run()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gbn_concurrent_session() {
    const WINDOW: usize = 4;
    const MSG_COUNT: usize = 6;

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    // Server side: sequential recv, echoes back.
    // Loop until Eof so that state == CloseWait when close() is called,
    // which takes the passive-close path (no FIN_WAIT_2 stall).
    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");
        loop {
            match conn.recv().await {
                Ok(data) => {
                    conn.send(&data).await.expect("echo");
                }
                Err(ConnError::Eof) => {
                    break;
                }
                Err(e) => panic!("server: {e}"),
            }
        }
        conn.close().await.expect("close");
    });

    // Client side: use the concurrent session API.
    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        let mut session = conn.run();

        // Build expected total payload for verification.
        let mut expected_total = Vec::new();
        for i in 0..MSG_COUNT {
            expected_total.extend_from_slice(format!("item-{i}").as_bytes());
        }

        // Send all messages through the channel (non-blocking).
        for i in 0..MSG_COUNT {
            let msg = format!("item-{i}");
            session.send(msg.into_bytes()).await.expect("session send");
        }

        // Collect echoes.  TCP is a byte stream, so the server's synchronous
        // send_segment may coalesce incoming data while blocked on window space.
        // We therefore collect all received bytes rather than expecting exactly
        // MSG_COUNT separate messages.
        let mut received_total = Vec::new();
        loop {
            match session.recv().await {
                Ok(data) => {
                    received_total.extend_from_slice(&data);
                    // Stop once we have all expected bytes.
                    if received_total.len() >= expected_total.len() {
                        break;
                    }
                }
                Err(ConnError::Eof) => break,
                Err(e) => panic!("client session recv: {e}"),
            }
        }

        session.close().await;
        (received_total, expected_total)
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    let (received_total, expected_total) = cr.unwrap();

    // Verify total bytes match (TCP byte-stream semantics).
    assert_eq!(
        received_total.len(),
        expected_total.len(),
        "total bytes mismatch: got {}, expected {}",
        received_total.len(),
        expected_total.len()
    );
    assert_eq!(
        received_total, expected_total,
        "byte content mismatch:\n  received: {:?}\n  expected: {:?}",
        String::from_utf8_lossy(&received_total),
        String::from_utf8_lossy(&expected_total)
    );
}

// ---------------------------------------------------------------------------
// Test 4b: concurrent session — no deadlock when window is full at close
//
// Regression test for the bug where `sender.can_send()` was part of Branch 1's
// select! guard.  When the send window was full (can_send() == false), the
// branch was disabled and the None produced by dropping send_tx was never
// observed, so FIN was never emitted and the event loop blocked forever.
//
// Failure mode: the `tokio::time::timeout` fires, indicating the session
// never reached CLOSED within the allowed window.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_deadlock_window_full_at_close() {
    // Large enough window that several segments are in-flight simultaneously,
    // making it likely (near-certain on loopback) that can_send() == false
    // when send_tx is dropped.
    const WINDOW: usize = 4;

    // More messages than WINDOW so the send channel still holds items when
    // the window fills.  The event loop will reach can_send() == false while
    // there are still payloads queued — the exact state that caused the bug.
    const MSG_COUNT: usize = WINDOW * 3;

    // Fail fast: if either side stalls, the test must not hang for minutes.
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    // Server: drain every message (ACKs are implicit) and close.
    // Deliberately does NOT echo back — the client's event loop has no
    // inbound data to process, so any stall is purely on the FIN path.
    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");
        loop {
            match conn.recv().await {
                Ok(_payload) => { /* ACK sent automatically; payload discarded */ }
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        conn.close().await.expect("server close");
    });

    // Client: queue more messages than the window in one burst (non-blocking
    // because the mpsc channel capacity >> MSG_COUNT), then drop send_tx
    // immediately.  The event loop will have can_send() == false for at
    // least part of this burst, which is the regression trigger.
    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        let session = conn.run();

        for i in 0..MSG_COUNT {
            session
                .send(format!("fill-{i}").into_bytes())
                .await
                .expect("send");
        }

        // Dropping send_tx here is the critical moment.  The event loop must
        // observe None and eventually emit FIN even if can_send() == false.
        session.close().await;
    });

    // Both tasks must finish within DEADLINE; if either stalls, a deadlock
    // has occurred and we want an immediate, informative failure.
    tokio::time::timeout(DEADLINE, async {
        let (sr, cr) = tokio::join!(server, client);
        sr.expect("server task panicked");
        cr.expect("client task panicked");
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "deadlock: concurrent session did not reach CLOSED within {DEADLINE:?}\n\
             (window was full when send_tx was dropped — FIN was never emitted)"
        )
    });
}

// ---------------------------------------------------------------------------
// Test 5: GBN sender unit-level — window boundary
// ---------------------------------------------------------------------------

#[test]
fn test_gbn_sender_window_boundary() {
    use tcp_over_udp::gbn_sender::GbnSender;

    let mut s = GbnSender::new(0, 3);
    s.cc.cwnd = 3; // bypass congestion window so window_size governs

    // Fill the window.
    for _ in 0..3u32 {
        let pkt = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(pkt);
    }
    assert!(!s.can_send(), "window should be full");
    assert_eq!(s.in_flight(), 3);

    // ACK the first two.
    let r = s.on_ack(8); // two 4-byte segments
    assert_eq!(r.acked_count, 2);
    assert!(s.can_send(), "one slot should have opened");
    assert_eq!(s.in_flight(), 1);

    // ACK the last one.
    let r = s.on_ack(12);
    assert_eq!(r.acked_count, 1);
    assert!(!s.has_unacked());
}

// ---------------------------------------------------------------------------
// Test 6: SR receiver unit-level — OOO segments buffered and delivered
// ---------------------------------------------------------------------------

#[test]
fn test_gbn_receiver_discard_ooo() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;

    let mut r = GbnReceiver::new(0);

    // seq=5 arrives before seq=0 — buffered in OOO map (SR), not discarded.
    // Returns false because nothing is delivered to the application yet.
    assert!(!r.on_segment(5, b"future"));
    assert_eq!(r.ack_number(), 0, "rcv_nxt must not advance on OOO segment");

    // seq=0 arrives in order — accepted; deliver_ooo fires and also delivers
    // the buffered seq=5, advancing rcv_nxt past both segments.
    assert!(r.on_segment(0, b"hello"));
    assert_eq!(r.ack_number(), 11, "rcv_nxt must advance past both segments");

    // seq=5 is now a duplicate (rcv_nxt=11 > 5) — discarded.
    assert!(!r.on_segment(5, b"future"));
    assert_eq!(r.ack_number(), 11, "duplicate must not advance rcv_nxt");
}

// ---------------------------------------------------------------------------
// Test 7: flush waits for all in-flight ACKs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gbn_flush_delivers_all() {
    const WINDOW: usize = 8;
    const MSG_COUNT: usize = 8;

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");
        let mut total = 0usize;
        loop {
            match conn.recv().await {
                Ok(data) => total += data.len(),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server: {e}"),
            }
            if total >= MSG_COUNT * 4 {
                break;
            }
        }
        conn.close().await.ok();
        total
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        for _ in 0..MSG_COUNT {
            conn.send(b"data").await.expect("send");
        }
        // flush() must block until every segment is ACKed.
        conn.flush().await.expect("flush");

        // After flush the sender window must be empty.
        assert!(!conn.sender.has_unacked(), "window not empty after flush");

        conn.close().await.expect("close");
    });

    let (sr, cr) = tokio::join!(server, client);
    let total = sr.unwrap();
    cr.unwrap();
    assert_eq!(total, MSG_COUNT * 4);
}

// ---------------------------------------------------------------------------
// Test 8: RTT estimator adapts — RTO falls below initial 1 s after exchanges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rtt_adapts_on_loopback() {
    // After a handful of loopback ping-pongs the RTT estimator should observe
    // sub-millisecond RTTs and reduce the RTO well below its 1 s initial value.

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    const ROUNDS: usize = 8;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");
        for _ in 0..ROUNDS {
            match conn.recv().await {
                Ok(data) => conn.send(&data).await.expect("echo"),
                Err(e) => panic!("server recv: {e}"),
            }
        }
        conn.close().await.ok();
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("connect");

        for i in 0..ROUNDS {
            let msg = format!("rtt-probe-{i}");
            conn.send(msg.as_bytes()).await.expect("send");
            conn.recv().await.expect("recv");
        }

        // After ROUNDS loopback echoes the RTO must be significantly below 1 s.
        let rto = conn.rtt.rto();
        assert!(
            rto < std::time::Duration::from_millis(500),
            "RTO should have adapted below 500 ms after loopback; got {rto:?}"
        );
        // SRTT must be present and tiny.
        let srtt = conn.rtt.srtt().expect("SRTT must be set after exchanges");
        assert!(
            srtt < std::time::Duration::from_millis(100),
            "SRTT should be near-zero on loopback; got {srtt:?}"
        );

        conn.close().await.ok();
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

// ---------------------------------------------------------------------------
// Test 9: Karn's algorithm — retransmit does not poison SRTT
// ---------------------------------------------------------------------------

#[test]
fn test_karn_retransmit_no_sample() {
    use tcp_over_udp::gbn_sender::GbnSender;

    let mut s = GbnSender::new(0, 2);
    s.cc.cwnd = 2; // bypass congestion window so both segments can be sent

    // Send two segments.
    let p1 = s.build_data_packet(vec![1u8; 8], 0, 8192);
    s.record_sent(p1);
    let p2 = s.build_data_packet(vec![2u8; 8], 0, 8192);
    s.record_sent(p2);

    // Simulate a timeout: both are retransmitted → tx_count becomes 2.
    s.on_retransmit();
    assert_eq!(s.window_entries().next().unwrap().tx_count, 2);

    // ACK for both: oldest was retransmitted → no RTT sample (Karn's algorithm).
    let r = s.on_ack(16);
    assert_eq!(r.acked_count, 2);
    assert!(
        r.rtt_sample.is_none(),
        "retransmitted oldest segment must suppress RTT sample"
    );
}

// ---------------------------------------------------------------------------
// Test 10: RTT estimator unit — RTO adapts after simulated delay
// ---------------------------------------------------------------------------

#[test]
fn test_rtt_estimator_adapts_to_delay() {
    use std::time::Duration;
    use tcp_over_udp::rtt::RttEstimator;

    let mut rtt = RttEstimator::new();

    // Feed 10 identical 50 ms samples.
    for _ in 0..10 {
        rtt.record_sample(Duration::from_millis(50));
    }

    let srtt = rtt.srtt().expect("SRTT must be set");
    // After 10 samples of 50 ms the SRTT should be close to 50 ms.
    assert!(
        srtt.as_millis().abs_diff(50) <= 5,
        "SRTT should ≈ 50 ms, got {srtt:?}"
    );

    // RTO = SRTT + 4·RTTVAR; with near-zero RTTVAR it should be close to SRTT.
    let rto = rtt.rto();
    assert!(
        rto >= srtt,
        "RTO must be ≥ SRTT, got rto={rto:?} srtt={srtt:?}"
    );
    assert!(
        rto < Duration::from_millis(500),
        "RTO should be well below 500 ms after stable 50 ms samples; got {rto:?}"
    );

    // Feed a sudden spike — RTTVAR should widen and RTO should increase.
    rtt.record_sample(Duration::from_millis(300));
    let rto_after_spike = rtt.rto();
    assert!(
        rto_after_spike > rto,
        "RTO must increase after a RTT spike; before={rto:?} after={rto_after_spike:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 11: cwnd starts at 1 and doubles per RTT during slow start
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_slow_start_doubles() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender, INITIAL_SSTHRESH};

    let mut s = GbnSender::new(0, 32);
    // Keep ssthresh high so slow start continues well past our test range.
    assert_eq!(s.cc.ssthresh, INITIAL_SSTHRESH);
    assert_eq!(s.cwnd(), 1);
    assert_eq!(s.cc.cc_state, CongestionState::SlowStart);

    // RTT 1: cwnd=1 → send 1 segment, ACK it → cwnd = 2.
    let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
    s.record_sent(p);
    let r = s.on_ack(4);
    s.on_ack_cc(r.acked_count);
    assert_eq!(s.cwnd(), 2, "SS: cwnd should be 2 after first RTT");
    assert_eq!(s.cc.cc_state, CongestionState::SlowStart);

    // RTT 2: cwnd=2 → send 2 segments, ACK both → cwnd = 4.
    for _ in 0..2 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    let r = s.on_ack(s.next_seq);
    s.on_ack_cc(r.acked_count);
    assert_eq!(s.cwnd(), 4, "SS: cwnd should be 4 after second RTT");
    assert_eq!(s.cc.cc_state, CongestionState::SlowStart);
}

// ---------------------------------------------------------------------------
// Test 12: cwnd grows by exactly 1 per RTT in congestion avoidance
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_congestion_avoidance_linear() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 32);
    // Manually place sender in CA phase at cwnd=4 via public fields.
    s.cc.ssthresh = 4;
    s.cc.cwnd = 4;
    s.cc.cc_state = CongestionState::CongestionAvoidance;

    // First "RTT": 4 ACKs arrive (one per in-flight segment) → cwnd = 5.
    s.on_ack_cc(4);
    assert_eq!(s.cwnd(), 5, "CA: cwnd must increase by 1 after one RTT's worth of ACKs");

    // Second "RTT": 5 ACKs → cwnd = 6.
    s.on_ack_cc(5);
    assert_eq!(s.cwnd(), 6, "CA: linear growth +1 per RTT");

    assert_eq!(s.cc.cc_state, CongestionState::CongestionAvoidance);
}

// ---------------------------------------------------------------------------
// Test 13: timeout halves ssthresh and resets cwnd to 1 (simulates loss)
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_timeout_halves_and_resets() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    // Start in CA with a large cwnd so we can fill 6 segments.
    let mut s = GbnSender::new(0, 32);
    s.cc.cwnd = 8;
    s.cc.ssthresh = 16;
    s.cc.cc_state = CongestionState::CongestionAvoidance;

    // Use record_sent() to put 6 segments in flight (cwnd=8, so this fits).
    for _ in 0..6 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.in_flight(), 6);

    // Simulate a timeout (packet loss detected via RTO expiry).
    s.on_timeout_cc();

    assert_eq!(s.cc.ssthresh, 3, "ssthresh = max(2, 6/2) = 3");
    assert_eq!(s.cwnd(), 1, "cwnd resets to 1 on timeout");
    assert_eq!(s.cc.cc_state, CongestionState::SlowStart, "must re-enter SlowStart");
}

// ---------------------------------------------------------------------------
// Test 14: 3 duplicate ACKs trigger fast retransmit entry (simulates loss)
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_triple_dup_ack_enters_fast_recovery() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    // Window size 8; inflate cwnd to allow 4 in-flight segments.
    let mut s = GbnSender::new(0, 8);
    s.cc.cwnd = 4;

    for _ in 0..4 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.in_flight(), 4);

    // 3 duplicate ACKs for send_base: no new data ACKed, just duplicates.
    for i in 1..=3u32 {
        let r = s.on_ack(s.send_base); // ack_num == send_base → dup-ACK
        assert!(r.dup_ack, "ACK #{i} must be flagged as duplicate");
        assert_eq!(s.dup_ack_count(), i, "dup_ack_count should be {i}");
    }

    s.on_triple_dup_ack_cc();

    // ssthresh = max(2, 4/2) = 2; cwnd = ssthresh + 3 = 5 (Reno inflation).
    assert_eq!(s.cc.ssthresh, 2, "ssthresh = max(2, 4/2) = 2");
    assert_eq!(s.cwnd(), 5, "cwnd = ssthresh + 3 = 5 (Reno fast recovery inflation)");
    assert_eq!(s.cc.cc_state, CongestionState::FastRecovery);
}

// ---------------------------------------------------------------------------
// Test 15: new ACK in fast recovery exits to congestion avoidance
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_fast_recovery_exit_on_new_ack() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 16);
    s.cc.ssthresh = 4;
    s.cc.cwnd = 7; // ssthresh + 3 (Reno fast recovery inflation)
    s.cc.cc_state = CongestionState::FastRecovery;

    // A genuine new ACK arrives → exit fast recovery, cwnd ← ssthresh.
    s.on_ack_cc(1);

    assert_eq!(s.cwnd(), 4, "exit FR: cwnd ← ssthresh = 4");
    assert_eq!(s.cc.cc_state, CongestionState::CongestionAvoidance);
}

// ---------------------------------------------------------------------------
// Test 17: < 3 duplicate ACKs (reordering) must NOT trigger fast recovery
// ---------------------------------------------------------------------------

#[test]
fn test_reordered_ack_below_threshold_no_fast_retransmit() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 8);
    s.cc.cwnd = 4;

    // Put 4 segments in flight (4-byte payloads → seq 0, 4, 8, 12).
    for _ in 0..4 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.in_flight(), 4);

    // 2 duplicate ACKs — could be mere reordering; must not enter FR.
    let r1 = s.on_ack(s.send_base);
    assert!(r1.dup_ack, "first dup-ACK must be flagged");
    let r2 = s.on_ack(s.send_base);
    assert!(r2.dup_ack, "second dup-ACK must be flagged");
    assert_eq!(s.dup_ack_count(), 2);
    assert_ne!(
        s.cc.cc_state,
        CongestionState::FastRecovery,
        "2 dup-ACKs must not enter fast recovery (reordering threshold is 3)"
    );

    // Reordering resolves: new ACK advances the window by 2 segments.
    let r3 = s.on_ack(8);
    assert_eq!(r3.acked_count, 2, "new ACK must ack 2 segments");
    assert_eq!(s.dup_ack_count(), 0, "new ACK must reset dup_ack_count");
    assert_ne!(
        s.cc.cc_state,
        CongestionState::FastRecovery,
        "cwnd must not enter fast recovery once reordering resolves"
    );
}

// ---------------------------------------------------------------------------
// Test 18: fast retransmit keeps cwnd > 1, unlike timeout which resets to 1
// ---------------------------------------------------------------------------

#[test]
fn test_fast_retransmit_cwnd_above_one_unlike_timeout() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    // ── Fast retransmit path ──────────────────────────────────────────────
    let mut s_fr = GbnSender::new(0, 8);
    s_fr.cc.cwnd = 4;
    for _ in 0..4 {
        let p = s_fr.build_data_packet(vec![0u8; 4], 0, 8192);
        s_fr.record_sent(p);
    }
    for _ in 0..3 {
        s_fr.on_ack(s_fr.send_base);
    }
    s_fr.on_triple_dup_ack_cc();

    assert_eq!(s_fr.cc.cc_state, CongestionState::FastRecovery);
    assert_ne!(
        s_fr.cwnd(), 1,
        "fast retransmit must NOT collapse cwnd to 1 — only a timeout does that"
    );
    let fr_cwnd = s_fr.cwnd(); // ssthresh+3 = 2+3 = 5

    // ── Timeout path — same initial conditions ────────────────────────────
    let mut s_to = GbnSender::new(0, 8);
    s_to.cc.cwnd = 4;
    for _ in 0..4 {
        let p = s_to.build_data_packet(vec![0u8; 4], 0, 8192);
        s_to.record_sent(p);
    }
    s_to.on_timeout_cc();

    assert_eq!(s_to.cwnd(), 1, "timeout must reset cwnd to 1");
    assert_eq!(s_to.cc.cc_state, CongestionState::SlowStart);

    assert!(
        fr_cwnd > s_to.cwnd(),
        "FR cwnd ({fr_cwnd}) must exceed timeout cwnd (1): fast retransmit preserves throughput"
    );
}

// ---------------------------------------------------------------------------
// Test 19: full fast recovery cycle driven end-to-end via on_ack()
// ---------------------------------------------------------------------------

#[test]
fn test_fast_recovery_full_cycle_via_on_ack() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 16);
    s.cc.cwnd = 4;

    // 4 segments in flight (seq 0, 4, 8, 12).
    for _ in 0..4 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.in_flight(), 4);

    // Three consecutive dup-ACKs via the real on_ack() path
    // (simulates segments 1–3 arriving but segment 0 being lost).
    let base = s.send_base;
    for i in 1..=3u32 {
        let r = s.on_ack(base);
        assert!(r.dup_ack, "ACK #{i} must be a duplicate");
        assert_eq!(s.dup_ack_count(), i);
    }

    // Enter fast recovery on the 3rd dup-ACK.
    s.on_triple_dup_ack_cc();
    let fr_ssthresh = s.cc.ssthresh;
    assert_eq!(fr_ssthresh, 2, "ssthresh = max(2, 4/2) = 2");
    assert_eq!(s.cwnd(), fr_ssthresh + 3, "cwnd = ssthresh + 3 in fast recovery");
    assert_eq!(s.cc.cc_state, CongestionState::FastRecovery);

    // A new (non-duplicate) ACK exits fast recovery → congestion avoidance.
    s.on_ack_cc(1);
    assert_eq!(s.cwnd(), fr_ssthresh, "FR→CA: cwnd must collapse to ssthresh");
    assert_eq!(
        s.cc.cc_state,
        CongestionState::CongestionAvoidance,
        "must enter congestion avoidance after fast recovery exit"
    );
}

// ---------------------------------------------------------------------------
// Test 16: integration — cwnd grows from slow start during loopback transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_congestion_control_cwnd_grows_on_loopback() {
    const WINDOW: usize = 16;
    const MSG_COUNT: usize = 20;

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");
        let mut total = 0usize;
        loop {
            match conn.recv().await {
                Ok(data) => total += data.len(),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server: {e}"),
            }
            if total >= MSG_COUNT * 4 {
                break;
            }
        }
        conn.close().await.ok();
        total
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        for _ in 0..MSG_COUNT {
            conn.send(b"data").await.expect("send");
        }
        conn.flush().await.expect("flush");

        // After a successful transfer cwnd must have grown beyond the initial 1.
        let cwnd = conn.sender.cwnd();
        assert!(
            cwnd > 1,
            "cwnd should have grown during slow start; got cwnd={cwnd}"
        );

        // RTT estimator must have samples.
        assert!(
            conn.rtt.srtt().is_some(),
            "SRTT must be set after exchanges"
        );

        conn.close().await.ok();
        cwnd
    });

    let (sr, cr) = tokio::join!(server, client);
    let total = sr.unwrap();
    let cwnd = cr.unwrap();
    assert_eq!(total, MSG_COUNT * 4);
    assert!(cwnd > 1, "final cwnd={cwnd} must reflect SS growth");
}

// ---------------------------------------------------------------------------
// Test 20: receiver advertises free space dynamically
// ---------------------------------------------------------------------------

#[test]
fn test_recv_window_advertises_free_space() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;

    let mut r = GbnReceiver::with_capacity(0, 100);
    assert_eq!(r.window_size(), 100, "full capacity advertised when empty");

    // Accept 40 bytes — free space drops to 60.
    assert!(r.on_segment(0, &[0u8; 40]));
    assert_eq!(r.window_size(), 60, "window must shrink by bytes buffered");

    // Application drains 20 bytes — free space rises to 80.
    let mut buf = [0u8; 20];
    r.read(&mut buf);
    assert_eq!(r.window_size(), 80, "window must grow after app drains buffer");
}

// ---------------------------------------------------------------------------
// Test 21: full receive buffer rejects subsequent in-order segments
// ---------------------------------------------------------------------------

#[test]
fn test_recv_full_buffer_rejects_segment() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;

    let mut r = GbnReceiver::with_capacity(0, 20);

    // Fill to capacity — must be accepted.
    assert!(r.on_segment(0, &[0u8; 20]), "segment filling capacity must be accepted");
    assert_eq!(r.window_size(), 0, "window must be zero when buffer is full");

    // Next in-order byte is rejected (no space).
    let rejected = r.on_segment(20, &[0u8; 1]);
    assert!(!rejected, "in-order segment must be rejected when buffer full");
    assert_eq!(r.rcv_nxt, 20, "rcv_nxt must not advance on full-buffer rejection");

    // Drain; the segment now fits.
    let mut drain = [0u8; 20];
    r.read(&mut drain);
    assert_eq!(r.window_size(), 20, "window must reopen after drain");
    assert!(r.on_segment(20, &[0u8; 1]), "segment must be accepted after drain");
}

// ---------------------------------------------------------------------------
// Test 22: sender pauses immediately when peer_rwnd drops to zero
// ---------------------------------------------------------------------------

#[test]
fn test_sender_pauses_on_zero_peer_rwnd() {
    use tcp_over_udp::gbn_sender::GbnSender;

    let mut s = GbnSender::new(0, 8);
    s.cc.cwnd = 4; // cwnd is permissive; rwnd should be the binding constraint

    // No in-flight segments; peer_rwnd = 0 → cannot send.
    s.update_peer_rwnd(0);
    assert!(!s.can_send(), "sender must pause when peer_rwnd == 0");

    // Open the window; sender should resume.
    s.update_peer_rwnd(100);
    assert!(s.can_send(), "sender must resume when peer_rwnd > 0");
}

// ---------------------------------------------------------------------------
// Test 23: bytes_in_flight tracks byte totals and bounds can_send
// ---------------------------------------------------------------------------

#[test]
fn test_bytes_in_flight_tracks_payload_size() {
    use tcp_over_udp::gbn_sender::GbnSender;

    let mut s = GbnSender::new(0, 8);
    s.cc.cwnd = 4;
    s.update_peer_rwnd(200);

    // Send 3 × 20-byte segments.
    for _ in 0..3 {
        let p = s.build_data_packet(vec![0u8; 20], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.bytes_in_flight(), 60, "bytes_in_flight must sum payloads");
    assert!(s.can_send(), "60 < 200 → can still send");

    // Tighten peer_rwnd to exactly in-flight; one more byte wouldn't fit.
    s.update_peer_rwnd(60);
    assert!(
        !s.can_send(),
        "bytes_in_flight == peer_rwnd → can_send must be false (strictly less-than check)"
    );

    // Loosen by 1 byte.
    s.update_peer_rwnd(61);
    assert!(s.can_send(), "61 > 60 → can_send must be true");
}

// ---------------------------------------------------------------------------
// Test 24: integration — small receive buffer, data flows correctly
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_flow_control_small_recv_buffer() {
    // Server has a 256-byte receive buffer; client uses the default.
    // 20 × 10-byte messages = 200 bytes total.  The test verifies that all
    // data is delivered correctly even with a constrained receiver buffer and
    // that the client observed the server's actual (non-default) rwnd.
    const WINDOW: usize = 4;
    const MSG_COUNT: usize = 20;
    const MSG_SIZE: usize = 10;
    const RECV_BUF: usize = 256;

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        // Server with restricted receive buffer.
        let mut conn = GbnConnection::accept_with_recv_buf(server_sock, WINDOW, RECV_BUF)
            .await
            .expect("accept");

        let mut received: Vec<Vec<u8>> = Vec::new();
        loop {
            match conn.recv().await {
                Ok(data) => received.push(data),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv error: {e}"),
            }
            if received.len() == MSG_COUNT {
                break;
            }
        }
        conn.close().await.ok();

        // Return the final peer_rwnd the server's sender observed from the
        // client's ACKs.  Should reflect the client's actual buffer (64 KiB
        // default), not the old static 8192.
        let peer_rwnd = conn.sender.peer_rwnd();
        (received, peer_rwnd)
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        for i in 0..MSG_COUNT {
            let msg = vec![i as u8; MSG_SIZE];
            conn.send(&msg).await.expect("client send");
        }
        conn.flush().await.expect("flush");

        // The client's sender.peer_rwnd reflects the server's advertised
        // window.  It must be ≤ RECV_BUF (the server's capacity), not the
        // old static 8192.
        let peer_rwnd = conn.sender.peer_rwnd();
        conn.close().await.ok();
        peer_rwnd
    });

    let (sr, cr) = tokio::join!(server, client);
    let (received, server_peer_rwnd) = sr.unwrap();
    let client_peer_rwnd = cr.unwrap();

    // All messages received correctly.
    assert_eq!(received.len(), MSG_COUNT, "server must receive all messages");
    for (i, chunk) in received.iter().enumerate() {
        assert_eq!(chunk.len(), MSG_SIZE);
        assert!(
            chunk.iter().all(|&b| b == i as u8),
            "message {i} corrupted"
        );
    }

    // Dynamic rwnd was observed: both sides advertised their real buffer sizes.
    assert!(
        client_peer_rwnd <= RECV_BUF,
        "client must have seen peer_rwnd ≤ RECV_BUF={RECV_BUF}, got {client_peer_rwnd}"
    );
    assert!(
        server_peer_rwnd > 8192,
        "server must have seen client's large default buffer (> 8192), got {server_peer_rwnd}"
    );
}

// ---------------------------------------------------------------------------
// Test 25: SR receiver buffers an OOO segment then delivers it when gap fills
// ---------------------------------------------------------------------------

#[test]
fn test_sr_receiver_buffers_and_delivers_ooo() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;

    let mut r = GbnReceiver::new(0);

    // seq=3 (OOO) arrives before seq=0 — buffered, nothing delivered.
    assert!(!r.on_segment(3, b"world"));
    assert_eq!(r.ack_number(), 0, "rcv_nxt must not advance for OOO");
    assert!(r.app_buffer.is_empty(), "OOO data must not appear in app_buffer yet");

    // seq=0 (in-order, 3 bytes) arrives — accepted, then OOO chain delivered.
    assert!(r.on_segment(0, b"hel"));
    assert_eq!(r.ack_number(), 8, "rcv_nxt must jump past OOO segment after chain delivery");
    assert_eq!(r.app_buffer.len(), 8, "both segments must be in app_buffer");

    let mut buf = [0u8; 8];
    let n = r.read(&mut buf);
    assert_eq!(n, 8);
    assert_eq!(&buf, b"helworld");
}

// ---------------------------------------------------------------------------
// Test 26: SR receiver delivers a multi-segment OOO chain (reverse arrival)
// ---------------------------------------------------------------------------

#[test]
fn test_sr_ooo_chain_delivery() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;

    let mut r = GbnReceiver::new(0);

    // Segments arrive in reverse order: last first, then second, then first.
    assert!(!r.on_segment(6, b"ccc")); // buffered
    assert!(!r.on_segment(3, b"bbb")); // buffered
    assert_eq!(r.ack_number(), 0, "rcv_nxt must stay at 0 while gap exists");

    // In-order arrival triggers full chain delivery.
    assert!(r.on_segment(0, b"aaa"));
    assert_eq!(r.ack_number(), 9, "all three segments delivered after gap fill");

    let mut buf = [0u8; 9];
    r.read(&mut buf);
    assert_eq!(&buf, b"aaabbbccc", "delivered bytes must be in sequence order");
}

// ---------------------------------------------------------------------------
// Test 27: SR sender — retransmit_oldest touches only the front entry
// ---------------------------------------------------------------------------

#[test]
fn test_sr_selective_retransmit_oldest_only() {
    use tcp_over_udp::gbn_sender::GbnSender;

    let mut s = GbnSender::new(0, 4);
    s.cc.cwnd = 3; // allow 3 in-flight

    // 3 segments of 8 bytes each (seq 0, 8, 16).
    for _ in 0..3 {
        let p = s.build_data_packet(vec![0u8; 8], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.in_flight(), 3);

    // SR timeout: only the oldest (seq=0) is retransmitted.
    let pkt = s.retransmit_oldest().expect("should have oldest segment");
    assert_eq!(pkt.header.seq, 0, "oldest segment must have seq=0");

    // Only the front entry has its tx_count and sent_at updated.
    let entries: Vec<_> = s.window_entries().collect();
    assert_eq!(entries[0].tx_count, 2, "oldest tx_count must be 2 after retransmit");
    assert_eq!(entries[1].tx_count, 1, "second segment must be untouched");
    assert_eq!(entries[2].tx_count, 1, "third segment must be untouched");
}

// ---------------------------------------------------------------------------
// Test 28: SR full cycle — OOO buffer + selective retransmit simulation
// ---------------------------------------------------------------------------

#[test]
fn test_sr_full_cycle() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;
    use tcp_over_udp::gbn_sender::GbnSender;

    // Sender: window=4, cwnd=4.
    let mut sender = GbnSender::new(0, 4);
    sender.cc.cwnd = 4;

    // Receiver: large buffer, expecting seq=0.
    let mut receiver = GbnReceiver::new(0);

    // "Send" 4 segments of 8 bytes (seq 0, 8, 16, 24).
    for _ in 0..4 {
        let pkt = sender.build_data_packet(vec![0u8; 8], 0, 8192);
        sender.record_sent(pkt);
    }
    assert_eq!(sender.in_flight(), 4);

    // Simulate network: segments 1–3 arrive at receiver; segment 0 was "lost".
    // With SR, these are buffered (not discarded) since seq=0 is still expected.
    assert!(!receiver.on_segment(8,  &[1u8; 8]));
    assert!(!receiver.on_segment(16, &[2u8; 8]));
    assert!(!receiver.on_segment(24, &[3u8; 8]));
    assert_eq!(receiver.ack_number(), 0, "gap at seq=0 must keep rcv_nxt at 0");
    assert!(receiver.app_buffer.is_empty(), "no data until gap is filled");

    // Selective retransmit: sender retransmits only seq=0 (not the full window).
    let retransmitted = sender.retransmit_oldest().expect("oldest must be available");
    assert_eq!(retransmitted.header.seq, 0, "SR must retransmit seq=0 only");

    // Segment 0 arrives (retransmission reaches receiver).
    assert!(receiver.on_segment(0, &[0u8; 8]));

    // SR chain delivery: all 4 segments now in app_buffer.
    assert_eq!(receiver.ack_number(), 32, "all 4 segments delivered via OOO chain");
    assert_eq!(receiver.app_buffer.len(), 32);

    // Cumulative ACK=32 clears the sender's entire window.
    let r = sender.on_ack(32);
    assert_eq!(r.acked_count, 4, "all 4 segments must be acked by cumulative ACK=32");
    assert!(!sender.has_unacked(), "sender window must be empty after full ACK");
}

// ---------------------------------------------------------------------------
// Test 30: active-close traverses the full state machine with TIME_WAIT
// ---------------------------------------------------------------------------
//
// The *client* calls `close()` first (active closer):
//   ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
//
// The *server* calls `close()` after receiving Eof (passive closer):
//   CLOSE_WAIT → LAST_ACK → CLOSED  (no TIME_WAIT)
//
// We use a non-zero MSL (50 ms) on the client so we can assert that the
// close() call actually lingered for at least 2×MSL = 100 ms.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_active_close_full_path() {
    use std::time::{Duration, Instant};
    use tokio::time::timeout;

    const WINDOW: usize = 4;
    const MSL: Duration = Duration::from_millis(50);
    const TWO_MSL: Duration = Duration::from_millis(100);
    // Extra slack for CI scheduling jitter.
    const SLACK: Duration = Duration::from_millis(500);
    const DEADLINE: Duration = Duration::from_secs(5);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW).await.unwrap();

        // Echo everything back.
        loop {
            match conn.recv().await {
                Ok(data) => conn.send(&data).await.unwrap(),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        // Passive close (state == CloseWait): send FIN, no TIME_WAIT.
        conn.close().await.unwrap();
    });

    let client = tokio::spawn(async move {
        let client_sock = ephemeral().await;
        let mut conn = GbnConnection::connect(client_sock, server_addr, WINDOW)
            .await
            .unwrap()
            .with_msl(MSL);    // Non-zero MSL so TIME_WAIT is observable.

        conn.send(b"ping").await.unwrap();
        let reply = conn.recv().await.unwrap();
        assert_eq!(reply, b"ping");

        // Active close: ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED.
        let t0 = Instant::now();
        conn.close().await.unwrap();
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= TWO_MSL,
            "TIME_WAIT must last at least 2×MSL={:?}; actual={:?}",
            TWO_MSL, elapsed,
        );
        assert!(
            elapsed < TWO_MSL + SLACK,
            "close() must not significantly over-wait; actual={:?}",
            elapsed,
        );
    });

    timeout(DEADLINE, async { let (s, c) = tokio::join!(server, client); s.unwrap(); c.unwrap(); })
        .await
        .expect("active-close full-path timed out — possible deadlock");
}

// ---------------------------------------------------------------------------
// Test 31: stale data segment arriving during TIME_WAIT is silently discarded
// ---------------------------------------------------------------------------
//
// A third socket injects a random data segment to the client's address while
// the client is lingering in TIME_WAIT.  `close()` must still complete normally
// and within the expected window.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_time_wait_absorbs_late_segment() {
    use std::time::{Duration, Instant};
    use tcp_over_udp::packet::{flags, Header, Packet};
    use tokio::time::timeout;

    const WINDOW: usize = 4;
    const MSL: Duration = Duration::from_millis(50);
    const TWO_MSL: Duration = Duration::from_millis(100);
    const SLACK: Duration = Duration::from_millis(500);
    const DEADLINE: Duration = Duration::from_secs(5);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW).await.unwrap();
        loop {
            match conn.recv().await {
                Ok(_) => {}
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        conn.close().await.unwrap();
    });

    let client_sock = ephemeral().await;
    let client_addr = client_sock.local_addr;

    let client = tokio::spawn(async move {
        let mut conn = GbnConnection::connect(client_sock, server_addr, WINDOW)
            .await
            .unwrap()
            .with_msl(MSL);

        conn.send(b"hello").await.unwrap();
        let t0 = Instant::now();
        conn.close().await.unwrap();
        let elapsed = t0.elapsed();
        assert!(elapsed >= TWO_MSL, "TIME_WAIT not observed; elapsed={:?}", elapsed);
        assert!(elapsed < TWO_MSL + SLACK, "close() over-waited; elapsed={:?}", elapsed);
    });

    // Injector: wait for client to reach TIME_WAIT, then send a stale segment.
    let injector = tokio::spawn(async move {
        // Sleep long enough for the handshake + data exchange + FIN exchange
        // to complete and TIME_WAIT to begin.
        tokio::time::sleep(Duration::from_millis(30)).await;

        let raw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stale = Packet {
            header: Header {
                seq: 0xDEAD_BEEF,
                ack: 0,
                flags: flags::ACK,
                window: 8192,
                checksum: 0,
            },
            options: vec![],
            payload: b"stale-segment".to_vec(),
        };
        let bytes = stale.encode().expect("encode failed");
        // Discard result — client may have already moved to CLOSED.
        let _ = raw.send_to(&bytes, client_addr.to_string().as_str()).await;
    });

    timeout(DEADLINE, async {
        let (s, c, _) = tokio::join!(server, client, injector);
        s.unwrap(); c.unwrap();
    })
    .await
    .expect("time_wait_absorbs_late_segment timed out");
}

// ---------------------------------------------------------------------------
// Test 32: duplicate FIN during TIME_WAIT is re-ACKed
// ---------------------------------------------------------------------------
//
// A third socket injects a duplicate FIN to the client while it lingers in
// TIME_WAIT.  The client must re-ACK the FIN and continue waiting until 2×MSL
// expires (TIME_WAIT cannot be shortened by a FIN flood).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_time_wait_reacks_duplicate_fin() {
    use std::time::{Duration, Instant};
    use tcp_over_udp::packet::{flags, Header, Packet};
    use tokio::time::timeout;

    const WINDOW: usize = 4;
    const MSL: Duration = Duration::from_millis(50);
    const TWO_MSL: Duration = Duration::from_millis(100);
    const SLACK: Duration = Duration::from_millis(500);
    const DEADLINE: Duration = Duration::from_secs(5);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    // Track the server's FIN sequence number so the injector can craft a
    // realistic duplicate.  A channel carries it out of the server task.
    let (fin_seq_tx, mut fin_seq_rx) = tokio::sync::mpsc::channel::<u32>(1);

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW).await.unwrap();
        loop {
            match conn.recv().await {
                Ok(_) => {}
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        // The server's FIN seq = conn.sender.next_seq.  Expose it before closing.
        let server_fin_seq = conn.sender.next_seq;
        let _ = fin_seq_tx.send(server_fin_seq).await;

        // Passive close.
        conn.close().await.unwrap();
    });

    let client_sock = ephemeral().await;
    let client_addr = client_sock.local_addr;

    let client = tokio::spawn(async move {
        let mut conn = GbnConnection::connect(client_sock, server_addr, WINDOW)
            .await
            .unwrap()
            .with_msl(MSL);

        conn.send(b"data").await.unwrap();
        // Wait for Eof (server sent FIN first in server's close_passive call)
        // or just close immediately — the active-close path still applies.
        let t0 = Instant::now();
        conn.close().await.unwrap();
        let elapsed = t0.elapsed();
        assert!(elapsed >= TWO_MSL, "TIME_WAIT not observed; elapsed={:?}", elapsed);
        assert!(elapsed < TWO_MSL + SLACK, "close() over-waited; elapsed={:?}", elapsed);
    });

    // Injector: wait for client to be in TIME_WAIT, then send a duplicate FIN.
    let injector = tokio::spawn(async move {
        // Wait for the server to report its FIN seq (or time out).
        let server_fin_seq = timeout(Duration::from_secs(2), fin_seq_rx.recv())
            .await
            .ok()
            .flatten()
            .unwrap_or(0);

        // A bit extra time to ensure client is in TIME_WAIT.
        tokio::time::sleep(Duration::from_millis(30)).await;

        let raw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dup_fin = Packet {
            header: Header {
                seq: server_fin_seq,
                ack: 0,
                flags: flags::FIN | flags::ACK,
                window: 8192,
                checksum: 0,
            },
            options: vec![],
            payload: vec![],
        };
        let bytes = dup_fin.encode().expect("encode failed");
        // Ignore result; client may have closed by now.
        let _ = raw.send_to(&bytes, client_addr.to_string().as_str()).await;
    });

    timeout(DEADLINE, async {
        let (s, c, _) = tokio::join!(server, client, injector);
        s.unwrap(); c.unwrap();
    })
    .await
    .expect("time_wait_reacks_duplicate_fin timed out");
}

// ---------------------------------------------------------------------------
// Test 33: MSS negotiation — each peer advertises its own MSS; the connection
// should settle on min(client_mss, server_mss).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mss_negotiation_min_selected() {
    const CLIENT_MSS: u16 = 800;
    const SERVER_MSS: u16 = 600; // smaller → wins
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let conn = Connection::accept_with_mss(server_sock, SERVER_MSS)
            .await
            .expect("accept");
        // Server sees negotiated = min(CLIENT_MSS, SERVER_MSS) = 600.
        assert_eq!(
            conn.negotiated_mss, 600,
            "server negotiated_mss should be min(800,600)=600"
        );
        let mut gbn = GbnConnection::from_connection(conn, 4);
        assert_eq!(gbn.mss(), 600, "GbnConnection should inherit negotiated MSS");
        // Drain one message so the test completes cleanly.
        loop {
            match gbn.recv().await {
                Ok(_) => {}
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        gbn.close().await.expect("server close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = Connection::connect_with_mss(sock, server_addr, CLIENT_MSS)
            .await
            .expect("connect");
        // Client also sees negotiated = 600.
        assert_eq!(
            conn.negotiated_mss, 600,
            "client negotiated_mss should be min(800,600)=600"
        );
        let mut gbn = GbnConnection::from_connection(conn, 4);
        assert_eq!(gbn.mss(), 600);
        gbn.send(b"hello").await.expect("send");
        gbn.flush().await.expect("flush");
        gbn.close().await.expect("close");
    });

    tokio::time::timeout(DEADLINE, async {
        let (s, c) = tokio::join!(server, client);
        s.unwrap();
        c.unwrap();
    })
    .await
    .expect("test_mss_negotiation_min_selected timed out");
}

// ---------------------------------------------------------------------------
// Test 34: backward-compatible peer (no MSS option) → fall back to DEFAULT_MSS.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mss_backward_compat_no_option() {
    // Both endpoints use the plain connect/accept (DEFAULT_MSS on both sides).
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let conn = Connection::accept(server_sock).await.expect("accept");
        assert_eq!(
            conn.negotiated_mss, DEFAULT_MSS,
            "both peers use DEFAULT_MSS when neither restricts it"
        );
        let mut gbn = GbnConnection::from_connection(conn, 1);
        loop {
            match gbn.recv().await {
                Ok(_) => {}
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        gbn.close().await.expect("close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = Connection::connect(sock, server_addr).await.expect("connect");
        assert_eq!(conn.negotiated_mss, DEFAULT_MSS);
        let mut gbn = GbnConnection::from_connection(conn, 1);
        gbn.send(b"ping").await.expect("send");
        gbn.flush().await.expect("flush");
        gbn.close().await.expect("close");
    });

    tokio::time::timeout(DEADLINE, async {
        let (s, c) = tokio::join!(server, client);
        s.unwrap();
        c.unwrap();
    })
    .await
    .expect("test_mss_backward_compat_no_option timed out");
}

// ---------------------------------------------------------------------------
// Test 35: segmentation — send a buffer larger than MSS; verify all bytes are
// received correctly and each transmitted segment is ≤ MSS bytes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_segmentation_respects_mss() {
    // Use a small MSS so a moderately-sized message spans multiple segments.
    const SMALL_MSS: u16 = 100;
    const MSG_SIZE: usize = 350; // ceil(350/100) = 4 segments of ≤100 bytes each
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    // Build MSG_SIZE bytes without the `0..350 as u8` overflow trap.
    let data: Vec<u8> = (0..MSG_SIZE).map(|i| (i % 256) as u8).collect();
    let expected = data.clone();

    let server = tokio::spawn(async move {
        let conn = Connection::accept_with_mss(server_sock, SMALL_MSS)
            .await
            .expect("accept");
        assert_eq!(conn.negotiated_mss, SMALL_MSS);
        let mut gbn = GbnConnection::from_connection(conn, 8);
        assert_eq!(gbn.mss(), SMALL_MSS);

        // Collect all data until the client closes the connection.
        let mut received: Vec<u8> = Vec::new();
        loop {
            match gbn.recv().await {
                Ok(chunk) => {
                    // Each segment delivered by recv() must be ≤ MSS bytes.
                    assert!(
                        chunk.len() <= SMALL_MSS as usize,
                        "received chunk len {} exceeds MSS {}",
                        chunk.len(),
                        SMALL_MSS
                    );
                    received.extend_from_slice(&chunk);
                }
                Err(ConnError::Eof) => break, // client FIN received
                Err(e) => panic!("server recv: {e}"),
            }
        }

        assert_eq!(received, expected, "reassembled data must match original");
        // State is now CloseWait; send our FIN back.
        gbn.close().await.expect("server close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = Connection::connect_with_mss(sock, server_addr, SMALL_MSS)
            .await
            .expect("connect");
        assert_eq!(conn.negotiated_mss, SMALL_MSS);
        let mut gbn = GbnConnection::from_connection(conn, 8);

        // send() transparently segments `data` into SMALL_MSS-sized chunks.
        gbn.send(&data).await.expect("send");
        gbn.flush().await.expect("flush");
        gbn.close().await.expect("close");
    });

    tokio::time::timeout(DEADLINE, async {
        let (s, c) = tokio::join!(server, client);
        s.unwrap();
        c.unwrap();
    })
    .await
    .expect("test_segmentation_respects_mss timed out");
}

// ---------------------------------------------------------------------------
// Test 36: Nagle holds small write until flush() drains it
// ---------------------------------------------------------------------------

/// Verify that with Nagle enabled, a sub-MSS write after a first segment
/// is held in the buffer and not transmitted until flush() is called.
/// All data must still arrive at the server in the correct order.
#[tokio::test(flavor = "multi_thread")]
async fn test_nagle_flush_delivers_all() {
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut gbn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("server accept");

        let mut received: Vec<u8> = Vec::new();
        loop {
            match gbn.recv().await {
                Ok(chunk) => received.extend_from_slice(&chunk),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        gbn.close().await.expect("server close");
        received
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut gbn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("client connect")
            .with_nagle(true);

        // First send: pipe is empty → sent immediately (Nagle allows it).
        gbn.send(b"first").await.expect("client send 1");
        // Second send: pipe is non-empty, 6 bytes < DEFAULT_MSS → held by Nagle.
        gbn.send(b"second").await.expect("client send 2");
        // flush() force-drains the Nagle buffer before waiting for ACKs.
        gbn.flush().await.expect("client flush");
        gbn.close().await.expect("client close");
    });

    let received = tokio::time::timeout(DEADLINE, async {
        let (s, c) = tokio::join!(server, client);
        c.unwrap();
        s.unwrap()
    })
    .await
    .expect("test_nagle_flush_delivers_all timed out");

    assert_eq!(received, b"firstsecond");
}

// ---------------------------------------------------------------------------
// Test 37: Nagle force-drains in recv() to prevent request/response deadlock
// ---------------------------------------------------------------------------

/// When Nagle is enabled and the client sends a small request then immediately
/// calls recv(), the Nagle buffer must be force-flushed before blocking so
/// that the server receives the request and can send its reply.
#[tokio::test(flavor = "multi_thread")]
async fn test_nagle_recv_prevents_deadlock() {
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    // Server: receive one request, reply, then close.
    let server = tokio::spawn(async move {
        let mut gbn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("server accept");

        // Wait for the client's request.
        let req = gbn.recv().await.expect("server recv request");
        assert_eq!(req, b"request");

        // Echo back.
        gbn.send(b"response").await.expect("server send response");
        // Drain until client closes.
        loop {
            match gbn.recv().await {
                Ok(_) => {}
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        gbn.close().await.expect("server close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut gbn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("client connect")
            .with_nagle(true);

        // send() with Nagle enabled: pipe is empty → sent immediately.
        gbn.send(b"request").await.expect("client send");

        // recv() must force-drain Nagle before blocking so the server
        // receives the request.  (Without force-drain this would deadlock.)
        let reply = gbn.recv().await.expect("client recv");
        assert_eq!(reply, b"response");

        gbn.close().await.expect("client close");
    });

    tokio::time::timeout(DEADLINE, async {
        let (s, c) = tokio::join!(server, client);
        s.unwrap();
        c.unwrap();
    })
    .await
    .expect("test_nagle_recv_prevents_deadlock timed out");
}

// ---------------------------------------------------------------------------
// Test 38: Nagle disabled (default) — each send dispatched immediately
// ---------------------------------------------------------------------------

/// With Nagle disabled (the default), each send() call dispatches its payload
/// as a separate segment regardless of pipe state.  All data must arrive.
#[tokio::test(flavor = "multi_thread")]
async fn test_nagle_disabled_sends_each_write_immediately() {
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut gbn = GbnConnection::accept(server_sock, 8)
            .await
            .expect("server accept");

        let mut received: Vec<u8> = Vec::new();
        loop {
            match gbn.recv().await {
                Ok(chunk) => received.extend_from_slice(&chunk),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        gbn.close().await.expect("server close");
        received
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        // Nagle is OFF by default (TCP_NODELAY semantics).
        let mut gbn = GbnConnection::connect(sock, server_addr, 8)
            .await
            .expect("client connect");

        for chunk in [b"a".as_slice(), b"bb", b"ccc", b"dddd"] {
            gbn.send(chunk).await.expect("client send");
        }
        gbn.flush().await.expect("client flush");
        gbn.close().await.expect("client close");
    });

    let received = tokio::time::timeout(DEADLINE, async {
        let (s, c) = tokio::join!(server, client);
        c.unwrap();
        s.unwrap()
    })
    .await
    .expect("test_nagle_disabled_sends_each_write_immediately timed out");

    assert_eq!(received, b"abbcccdddd");
}

// ---------------------------------------------------------------------------
// Test 36: SACK — reordering does not cause spurious retransmit
// ---------------------------------------------------------------------------
//
// Four segments are sent.  Segments 1–3 (seq 8, 16, 24) arrive at the
// receiver before segment 0 (seq 0).  The receiver builds a SACK block
// [{8, 32}] covering all three buffered segments.  When the sender processes
// that SACK, entries for seq 8, 16, and 24 become sacked.
//
// Consequence: `retransmit_oldest()` skips the sacked entries and returns
// seq=0 — the truly missing segment — as the only retransmit candidate.
// `sr_retransmit_count` rises to exactly 1 when we call `retransmit_oldest()`
// once, which is correct.  No additional retransmit occurs for the already-
// received segments.
// ---------------------------------------------------------------------------

#[test]
fn test_sack_reorder_no_spurious_retransmit() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;
    use tcp_over_udp::gbn_sender::GbnSender;
    use tcp_over_udp::packet::SackBlock;

    // Sender: window=4, cwnd=4, 4 segments of 8 bytes each.
    let mut sender = GbnSender::new(0, 4);
    sender.cc.cwnd = 4;
    for _ in 0..4 {
        let pkt = sender.build_data_packet(vec![0u8; 8], 0, 8192);
        sender.record_sent(pkt);
    }
    assert_eq!(sender.in_flight(), 4);

    // Receiver expects seq=0.
    let mut receiver = GbnReceiver::new(0);

    // Network reordering: segments 1–3 arrive first (seq 8, 16, 24), all OOO.
    assert!(!receiver.on_segment(8,  &[1u8; 8]));
    assert!(!receiver.on_segment(16, &[2u8; 8]));
    assert!(!receiver.on_segment(24, &[3u8; 8]));
    assert_eq!(receiver.ack_number(), 0, "rcv_nxt must not advance while seq=0 is missing");

    // Receiver advertises one merged SACK block covering [8, 32).
    let sack = receiver.sack_blocks();
    assert_eq!(sack.len(), 1, "three contiguous OOO segments must merge into one block");
    assert_eq!(sack[0], SackBlock { left: 8, right: 32 });

    // Sender marks entries covered by the SACK block as sacked.
    sender.process_sack(&sack);

    // Only `retransmit_oldest` for the truly missing segment (seq=0) should fire.
    let pkt = sender
        .retransmit_oldest()
        .expect("seq=0 must be the retransmit candidate");
    assert_eq!(pkt.header.seq, 0, "only the non-sacked segment must be retransmitted");
    assert_eq!(
        sender.sr_retransmit_count(),
        1,
        "exactly one retransmit for the missing segment; none for sacked ones"
    );

    // Deliver the retransmitted seq=0 — triggers OOO chain delivery.
    assert!(receiver.on_segment(0, &[0u8; 8]));
    assert_eq!(receiver.ack_number(), 32, "all four segments delivered after gap fill");

    // Cumulative ACK=32 clears the sender window.
    let r = sender.on_ack(32);
    assert_eq!(r.acked_count, 4, "all four segments must be cumulatively acked");
    assert!(!sender.has_unacked());
}

// ---------------------------------------------------------------------------
// Test 37: SACK — only the lost middle segment is retransmitted
// ---------------------------------------------------------------------------
//
// Three segments are sent.  The first (seq 0) and third (seq 16) arrive at
// the receiver; the middle one (seq 8) is lost.  The receiver ACKs seq=8
// cumulatively (the first segment) and includes a SACK block [{16, 24}] for
// the buffered third segment.  After the cumulative ACK advances the sender
// window past seq=0, `retransmit_oldest()` must return seq=8 — not seq=16
// (which is already sacked).
// ---------------------------------------------------------------------------

#[test]
fn test_sack_middle_segment_loss() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;
    use tcp_over_udp::gbn_sender::GbnSender;
    use tcp_over_udp::packet::SackBlock;

    // Sender: window=3, cwnd=3, three segments of 8 bytes each.
    let mut sender = GbnSender::new(0, 3);
    sender.cc.cwnd = 3;
    for _ in 0..3 {
        let pkt = sender.build_data_packet(vec![0u8; 8], 0, 8192);
        sender.record_sent(pkt);
    }
    assert_eq!(sender.in_flight(), 3);

    // Receiver expects seq=0.
    let mut receiver = GbnReceiver::new(0);

    // seg 0 (seq=0) arrives in-order → accepted.
    assert!(receiver.on_segment(0, &[0u8; 8]));
    assert_eq!(receiver.ack_number(), 8);

    // seg 1 (seq=8) is LOST — never delivered.

    // seg 2 (seq=16) arrives OOO → buffered.
    assert!(!receiver.on_segment(16, &[2u8; 8]));
    assert_eq!(receiver.ack_number(), 8, "rcv_nxt stays at 8 while seq=8 is missing");

    // Receiver reports one SACK block for the buffered segment.
    let sack = receiver.sack_blocks();
    assert_eq!(sack.len(), 1);
    assert_eq!(sack[0], SackBlock { left: 16, right: 24 });

    // Cumulative ACK=8 pops seq=0 from the sender window.
    let r = sender.on_ack(8);
    assert_eq!(r.acked_count, 1);

    // Sender marks the remaining window entries using SACK.
    sender.process_sack(&sack);

    // Window now holds seq=8 (not sacked) and seq=16 (sacked).
    // retransmit_oldest must return seq=8 — skipping seq=16.
    let pkt = sender
        .retransmit_oldest()
        .expect("seq=8 must be the retransmit candidate");
    assert_eq!(pkt.header.seq, 8, "middle segment must be the sole retransmit target");
    assert_eq!(sender.sr_retransmit_count(), 1);

    // Deliver the retransmitted seq=8 → OOO chain delivers seq=8 then seq=16.
    assert!(receiver.on_segment(8, &[1u8; 8]));
    assert_eq!(receiver.ack_number(), 24, "all three segments delivered");

    // Cumulative ACK=24 clears the window.
    let r2 = sender.on_ack(24);
    assert_eq!(r2.acked_count, 2, "seq=8 and seq=16 cleared by ACK=24");
    assert!(!sender.has_unacked());
}

// ---------------------------------------------------------------------------
// Test 38: SACK — two disjoint gaps are each retransmitted exactly once
// ---------------------------------------------------------------------------
//
// Six segments are sent.  Segments at seq 8 and seq 32 are lost; the other
// four arrive.  The receiver builds two disjoint SACK blocks: [{16,32}] and
// [{40,48}].  The sender uses those blocks to skip sacked entries and
// retransmits only seq=8 and seq=32 — total `sr_retransmit_count` == 2.
// ---------------------------------------------------------------------------

#[test]
fn test_sack_two_disjoint_gaps() {
    use tcp_over_udp::gbn_receiver::GbnReceiver;
    use tcp_over_udp::gbn_sender::GbnSender;
    use tcp_over_udp::packet::SackBlock;

    // Sender: window=6, cwnd=6, six segments of 8 bytes each (seq 0…40).
    let mut sender = GbnSender::new(0, 6);
    sender.cc.cwnd = 6;
    for _ in 0..6 {
        let pkt = sender.build_data_packet(vec![0u8; 8], 0, 8192);
        sender.record_sent(pkt);
    }
    // Segments: seq=0, 8, 16, 24, 32, 40.
    assert_eq!(sender.in_flight(), 6);

    // Receiver expects seq=0.
    let mut receiver = GbnReceiver::new(0);

    // seq=0 arrives in-order → delivered.
    assert!(receiver.on_segment(0, &[0u8; 8]));
    assert_eq!(receiver.ack_number(), 8);

    // seq=8  LOST (never arrives).

    // seq=16, seq=24 arrive OOO → buffered (gap at 8).
    assert!(!receiver.on_segment(16, &[2u8; 8]));
    assert!(!receiver.on_segment(24, &[3u8; 8]));

    // seq=32 LOST (never arrives).

    // seq=40 arrives OOO → buffered (gap at 32).
    assert!(!receiver.on_segment(40, &[5u8; 8]));
    assert_eq!(receiver.ack_number(), 8, "rcv_nxt stays at 8 — gap at seq=8");

    // Receiver has two disjoint SACK blocks.
    let sack = receiver.sack_blocks();
    assert_eq!(sack.len(), 2, "two disjoint OOO regions must produce two blocks");
    assert_eq!(sack[0], SackBlock { left: 16, right: 32 });
    assert_eq!(sack[1], SackBlock { left: 40, right: 48 });

    // Cumulative ACK=8 pops seq=0.
    let r = sender.on_ack(8);
    assert_eq!(r.acked_count, 1);

    // Apply SACK — window now: seq=8(!), seq=16(✓), seq=24(✓), seq=32(!), seq=40(✓).
    sender.process_sack(&sack);

    // First retransmit: seq=8 (oldest non-sacked).
    let pkt1 = sender.retransmit_oldest().expect("seq=8 must be retransmit candidate");
    assert_eq!(pkt1.header.seq, 8);

    // Deliver seq=8 to receiver → chain delivers seq=8, 16, 24 → ack=32.
    assert!(receiver.on_segment(8, &[1u8; 8]));
    assert_eq!(receiver.ack_number(), 32, "gap at 8 filled; delivers up to 32");

    // Cumulative ACK=32 pops seq=8, 16, 24 from sender.
    let r2 = sender.on_ack(32);
    assert_eq!(r2.acked_count, 3);
    // Remaining window: seq=32(!), seq=40(✓).

    // Re-apply the second SACK block (sender still knows about seq=40).
    sender.process_sack(&[SackBlock { left: 40, right: 48 }]);

    // Second retransmit: seq=32 (oldest remaining non-sacked).
    let pkt2 = sender.retransmit_oldest().expect("seq=32 must be retransmit candidate");
    assert_eq!(pkt2.header.seq, 32);

    // Deliver seq=32 → chain delivers seq=32, 40 → ack=48.
    assert!(receiver.on_segment(32, &[4u8; 8]));
    assert_eq!(receiver.ack_number(), 48, "all six segments delivered");

    // Final cumulative ACK=48 clears the window.
    let r3 = sender.on_ack(48);
    assert_eq!(r3.acked_count, 2, "seq=32 and seq=40 cleared by ACK=48");
    assert!(!sender.has_unacked());

    // Exactly two retransmits occurred — one per gap.
    assert_eq!(sender.sr_retransmit_count(), 2, "exactly two retransmits for two gaps");
}

// ---------------------------------------------------------------------------
// Window Scaling Integration Tests
// ---------------------------------------------------------------------------

/// Verify that window scaling is negotiated during GbnConnection handshake.
#[tokio::test]
async fn test_gbn_window_scale_negotiation() {
    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let conn = GbnConnection::accept(server_sock, 4)
            .await
            .expect("accept");

        // Window scaling should be negotiated.
        assert!(
            conn.snd_wscale().is_some(),
            "server should have negotiated snd_wscale"
        );
        assert!(
            conn.rcv_wscale().is_some(),
            "server should have negotiated rcv_wscale"
        );

        // Scale factors should be within valid TCP range (0-14).
        let snd = conn.snd_wscale().unwrap();
        let rcv = conn.rcv_wscale().unwrap();
        assert!(snd <= 14, "snd_wscale must be <= 14");
        assert!(rcv <= 14, "rcv_wscale must be <= 14");

        conn
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let conn = GbnConnection::connect(sock, server_addr, 4)
            .await
            .expect("connect");

        // Window scaling should be negotiated.
        assert!(
            conn.snd_wscale().is_some(),
            "client should have negotiated snd_wscale"
        );
        assert!(
            conn.rcv_wscale().is_some(),
            "client should have negotiated rcv_wscale"
        );

        conn
    });

    let (sr, cr) = tokio::join!(server, client);
    let server_conn = sr.unwrap();
    let client_conn = cr.unwrap();

    // Both sides should have the same scale factors.
    assert_eq!(
        server_conn.snd_wscale(),
        client_conn.snd_wscale(),
        "both sides should negotiate the same snd_wscale"
    );
    assert_eq!(
        server_conn.rcv_wscale(),
        client_conn.rcv_wscale(),
        "both sides should negotiate the same rcv_wscale"
    );
}

/// Test data transfer with window scaling enabled.
/// This verifies that window scaling works correctly for actual data exchange.
#[tokio::test]
async fn test_gbn_window_scale_data_transfer() {
    const WINDOW: usize = 8;
    const DATA_SIZE: usize = 32 * 1024; // 32 KiB

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");

        // Verify window scaling is enabled.
        assert!(conn.snd_wscale().is_some(), "window scaling should be enabled");

        // Receive all data.
        let mut total_received = 0;
        loop {
            match conn.recv().await {
                Ok(data) => {
                    total_received += data.len();
                    if total_received >= DATA_SIZE {
                        break;
                    }
                }
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv error: {e:?}"),
            }
        }

        assert_eq!(total_received, DATA_SIZE, "should receive all data");
        conn.close().await.ok();
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        // Verify window scaling is enabled.
        assert!(conn.snd_wscale().is_some(), "window scaling should be enabled");

        // Send data in chunks.
        let data = vec![0xABu8; DATA_SIZE];
        conn.send(&data).await.expect("client send");
        conn.close().await.expect("client close");
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

/// Test large data transfer that benefits from window scaling.
/// With a scale factor of 7, we can advertise windows up to 8 MiB,
/// which allows for high bandwidth-delay product scenarios.
#[tokio::test]
async fn test_gbn_large_transfer_with_window_scaling() {
    const WINDOW: usize = 16;
    const DATA_SIZE: usize = 128 * 1024; // 128 KiB - larger transfer

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");

        // Use a large receive buffer to allow window scaling to be effective.
        // The default is 64 KiB, which with scale factor 7 allows advertising
        // windows up to 64 KiB (limited by actual buffer size).

        let mut total_received = 0;
        let mut received_data = Vec::new();

        loop {
            match conn.recv().await {
                Ok(data) => {
                    total_received += data.len();
                    received_data.extend_from_slice(&data);
                    if total_received >= DATA_SIZE {
                        break;
                    }
                }
                Err(ConnError::Eof) => break,
                Err(e) => panic!("server recv error: {e:?}"),
            }
        }

        assert_eq!(total_received, DATA_SIZE, "should receive all data");

        // Verify data integrity.
        for (i, &byte) in received_data.iter().enumerate() {
            let expected = (i % 256) as u8;
            assert_eq!(byte, expected, "data corruption at byte {i}");
        }

        conn.close().await.ok();
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        // Create test data with a recognizable pattern.
        let data: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 256) as u8).collect();

        conn.send(&data).await.expect("client send");
        conn.close().await.expect("client close");
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}

/// Test bidirectional transfer with window scaling.
#[tokio::test]
async fn test_gbn_bidirectional_with_window_scaling() {
    const WINDOW: usize = 8;
    const MSG_SIZE: usize = 16 * 1024; // 16 KiB each way

    let server_sock = ephemeral().await;
    let server_addr = server_sock.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");

        // Receive client's data.
        let mut received = Vec::new();
        while received.len() < MSG_SIZE {
            match conn.recv().await {
                Ok(data) => received.extend_from_slice(&data),
                Err(e) => panic!("server recv error: {e:?}"),
            }
        }

        // Verify received data.
        assert_eq!(received.len(), MSG_SIZE);
        for (i, &byte) in received.iter().enumerate() {
            assert_eq!(byte, 0xAA, "unexpected byte at position {i}");
        }

        // Send response back.
        let response = vec![0xBBu8; MSG_SIZE];
        conn.send(&response).await.expect("server send");
        conn.close().await.expect("server close");
    });

    let client = tokio::spawn(async move {
        let sock = ephemeral().await;
        let mut conn = GbnConnection::connect(sock, server_addr, WINDOW)
            .await
            .expect("connect");

        // Send data to server.
        let request = vec![0xAAu8; MSG_SIZE];
        conn.send(&request).await.expect("client send");

        // Receive response.
        let mut received = Vec::new();
        while received.len() < MSG_SIZE {
            match conn.recv().await {
                Ok(data) => received.extend_from_slice(&data),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("client recv error: {e:?}"),
            }
        }

        // Verify response.
        assert_eq!(received.len(), MSG_SIZE);
        for (i, &byte) in received.iter().enumerate() {
            assert_eq!(byte, 0xBB, "unexpected byte at position {i}");
        }

        conn.close().await.expect("client close");
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    cr.unwrap();
}
