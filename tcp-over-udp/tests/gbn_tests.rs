//! Integration tests for the Go-Back-N sliding-window layer.
//!
//! Each test spins up two in-process GBN endpoints talking over the loopback
//! interface.  Both sides are spawned as separate tokio tasks so they can make
//! progress concurrently without blocking each other.

use tcp_over_udp::{
    connection::ConnError,
    gbn_connection::GbnConnection,
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
    let server = tokio::spawn(async move {
        let mut conn = GbnConnection::accept(server_sock, WINDOW)
            .await
            .expect("accept");
        for _ in 0..MSG_COUNT {
            match conn.recv().await {
                Ok(data) => conn.send(&data).await.expect("echo"),
                Err(ConnError::Eof) => break,
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

        // Send all messages through the channel (non-blocking).
        for i in 0..MSG_COUNT {
            let msg = format!("item-{i}");
            session.send(msg.into_bytes()).await.expect("session send");
        }

        // Collect echoes.
        let mut replies = Vec::new();
        for _ in 0..MSG_COUNT {
            match session.recv().await {
                Ok(data) => replies.push(data),
                Err(ConnError::Eof) => break,
                Err(e) => panic!("client session recv: {e}"),
            }
        }

        session.close().await;
        replies
    });

    let (sr, cr) = tokio::join!(server, client);
    sr.unwrap();
    let replies = cr.unwrap();

    assert_eq!(replies.len(), MSG_COUNT);
    for (i, r) in replies.iter().enumerate() {
        let expected = format!("item-{i}");
        assert_eq!(r, expected.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Test 5: GBN sender unit-level — window boundary
// ---------------------------------------------------------------------------

#[test]
fn test_gbn_sender_window_boundary() {
    use tcp_over_udp::gbn_sender::GbnSender;

    let mut s = GbnSender::new(0, 3);
    s.cwnd = 3; // bypass congestion window so window_size governs

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
    s.cwnd = 2; // bypass congestion window so both segments can be sent

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
    assert_eq!(s.ssthresh(), INITIAL_SSTHRESH);
    assert_eq!(s.cwnd(), 1);
    assert_eq!(*s.cc_state(), CongestionState::SlowStart);

    // RTT 1: cwnd=1 → send 1 segment, ACK it → cwnd = 2.
    let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
    s.record_sent(p);
    let r = s.on_ack(4);
    s.on_ack_cc(r.acked_count);
    assert_eq!(s.cwnd(), 2, "SS: cwnd should be 2 after first RTT");
    assert_eq!(*s.cc_state(), CongestionState::SlowStart);

    // RTT 2: cwnd=2 → send 2 segments, ACK both → cwnd = 4.
    for _ in 0..2 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    let r = s.on_ack(s.next_seq);
    s.on_ack_cc(r.acked_count);
    assert_eq!(s.cwnd(), 4, "SS: cwnd should be 4 after second RTT");
    assert_eq!(*s.cc_state(), CongestionState::SlowStart);
}

// ---------------------------------------------------------------------------
// Test 12: cwnd grows by exactly 1 per RTT in congestion avoidance
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_congestion_avoidance_linear() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 32);
    // Manually place sender in CA phase at cwnd=4 via public fields.
    s.ssthresh = 4;
    s.cwnd = 4;
    s.cc_state = CongestionState::CongestionAvoidance;

    // First "RTT": 4 ACKs arrive (one per in-flight segment) → cwnd = 5.
    s.on_ack_cc(4);
    assert_eq!(s.cwnd(), 5, "CA: cwnd must increase by 1 after one RTT's worth of ACKs");

    // Second "RTT": 5 ACKs → cwnd = 6.
    s.on_ack_cc(5);
    assert_eq!(s.cwnd(), 6, "CA: linear growth +1 per RTT");

    assert_eq!(*s.cc_state(), CongestionState::CongestionAvoidance);
}

// ---------------------------------------------------------------------------
// Test 13: timeout halves ssthresh and resets cwnd to 1 (simulates loss)
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_timeout_halves_and_resets() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    // Start in CA with a large cwnd so we can fill 6 segments.
    let mut s = GbnSender::new(0, 32);
    s.cwnd = 8;
    s.ssthresh = 16;
    s.cc_state = CongestionState::CongestionAvoidance;

    // Use record_sent() to put 6 segments in flight (cwnd=8, so this fits).
    for _ in 0..6 {
        let p = s.build_data_packet(vec![0u8; 4], 0, 8192);
        s.record_sent(p);
    }
    assert_eq!(s.in_flight(), 6);

    // Simulate a timeout (packet loss detected via RTO expiry).
    s.on_timeout_cc();

    assert_eq!(s.ssthresh(), 3, "ssthresh = max(2, 6/2) = 3");
    assert_eq!(s.cwnd(), 1, "cwnd resets to 1 on timeout");
    assert_eq!(*s.cc_state(), CongestionState::SlowStart, "must re-enter SlowStart");
}

// ---------------------------------------------------------------------------
// Test 14: 3 duplicate ACKs trigger fast retransmit entry (simulates loss)
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_triple_dup_ack_enters_fast_recovery() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    // Window size 8; inflate cwnd to allow 4 in-flight segments.
    let mut s = GbnSender::new(0, 8);
    s.cwnd = 4;

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
    assert_eq!(s.ssthresh(), 2, "ssthresh = max(2, 4/2) = 2");
    assert_eq!(s.cwnd(), 5, "cwnd = ssthresh + 3 = 5 (Reno fast recovery inflation)");
    assert_eq!(*s.cc_state(), CongestionState::FastRecovery);
}

// ---------------------------------------------------------------------------
// Test 15: new ACK in fast recovery exits to congestion avoidance
// ---------------------------------------------------------------------------

#[test]
fn test_cwnd_fast_recovery_exit_on_new_ack() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 16);
    s.ssthresh = 4;
    s.cwnd = 7; // ssthresh + 3 (Reno fast recovery inflation)
    s.cc_state = CongestionState::FastRecovery;

    // A genuine new ACK arrives → exit fast recovery, cwnd ← ssthresh.
    s.on_ack_cc(1);

    assert_eq!(s.cwnd(), 4, "exit FR: cwnd ← ssthresh = 4");
    assert_eq!(*s.cc_state(), CongestionState::CongestionAvoidance);
}

// ---------------------------------------------------------------------------
// Test 17: < 3 duplicate ACKs (reordering) must NOT trigger fast recovery
// ---------------------------------------------------------------------------

#[test]
fn test_reordered_ack_below_threshold_no_fast_retransmit() {
    use tcp_over_udp::gbn_sender::{CongestionState, GbnSender};

    let mut s = GbnSender::new(0, 8);
    s.cwnd = 4;

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
        *s.cc_state(),
        CongestionState::FastRecovery,
        "2 dup-ACKs must not enter fast recovery (reordering threshold is 3)"
    );

    // Reordering resolves: new ACK advances the window by 2 segments.
    let r3 = s.on_ack(8);
    assert_eq!(r3.acked_count, 2, "new ACK must ack 2 segments");
    assert_eq!(s.dup_ack_count(), 0, "new ACK must reset dup_ack_count");
    assert_ne!(
        *s.cc_state(),
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
    s_fr.cwnd = 4;
    for _ in 0..4 {
        let p = s_fr.build_data_packet(vec![0u8; 4], 0, 8192);
        s_fr.record_sent(p);
    }
    for _ in 0..3 {
        s_fr.on_ack(s_fr.send_base);
    }
    s_fr.on_triple_dup_ack_cc();

    assert_eq!(*s_fr.cc_state(), CongestionState::FastRecovery);
    assert_ne!(
        s_fr.cwnd(), 1,
        "fast retransmit must NOT collapse cwnd to 1 — only a timeout does that"
    );
    let fr_cwnd = s_fr.cwnd(); // ssthresh+3 = 2+3 = 5

    // ── Timeout path — same initial conditions ────────────────────────────
    let mut s_to = GbnSender::new(0, 8);
    s_to.cwnd = 4;
    for _ in 0..4 {
        let p = s_to.build_data_packet(vec![0u8; 4], 0, 8192);
        s_to.record_sent(p);
    }
    s_to.on_timeout_cc();

    assert_eq!(s_to.cwnd(), 1, "timeout must reset cwnd to 1");
    assert_eq!(*s_to.cc_state(), CongestionState::SlowStart);

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
    s.cwnd = 4;

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
    let fr_ssthresh = s.ssthresh();
    assert_eq!(fr_ssthresh, 2, "ssthresh = max(2, 4/2) = 2");
    assert_eq!(s.cwnd(), fr_ssthresh + 3, "cwnd = ssthresh + 3 in fast recovery");
    assert_eq!(*s.cc_state(), CongestionState::FastRecovery);

    // A new (non-duplicate) ACK exits fast recovery → congestion avoidance.
    s.on_ack_cc(1);
    assert_eq!(s.cwnd(), fr_ssthresh, "FR→CA: cwnd must collapse to ssthresh");
    assert_eq!(
        *s.cc_state(),
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
    s.cwnd = 4; // cwnd is permissive; rwnd should be the binding constraint

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
    s.cwnd = 4;
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
    s.cwnd = 3; // allow 3 in-flight

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
    sender.cwnd = 4;

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
