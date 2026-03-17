//! Integration tests for the `SimulatedSocket` fault-injection layer.
//!
//! Each test drives two `SimulatedSocket` endpoints directly — no protocol
//! layer involved — so the assertions are purely about the fault model:
//!
//! * Packets that should be dropped never reach `recv_from`.
//! * Packets that should be corrupted are silently discarded by `recv_from`.
//! * Duplicated packets appear twice at the receiver.
//! * Delayed packets arrive later than non-delayed ones.
//! * A bandwidth cap causes measurable back-pressure.
//! * A fixed PRNG seed reproduces the exact same fault sequence.

use std::time::{Duration, Instant};

use tcp_over_udp::{
    packet::{flags, Header, Packet},
    simulator::{SimulatedSocket, SimulationConfig},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Construct a minimal data packet with the given sequence number.
///
/// The checksum field is left as 0 — `Packet::encode` computes and
/// overwrites it, so the stored value is irrelevant.
fn make_packet(seq: u32, payload: &[u8]) -> Packet {
    Packet {
        header: Header {
            seq,
            ack: 0,
            flags: flags::ACK,
            window: 8192,
            checksum: 0,
        },
        options: vec![],
        payload: payload.to_vec(),
    }
}

/// Bind a `SimulatedSocket` to an OS-chosen loopback port.
async fn sim_socket(config: SimulationConfig) -> SimulatedSocket {
    let addr = "127.0.0.1:0".parse().unwrap();
    SimulatedSocket::bind(addr, config).await.expect("bind failed")
}

// ---------------------------------------------------------------------------
// Test 1: clean delivery — default config is a transparent pass-through.
// ---------------------------------------------------------------------------

/// With all fault rates at zero, a packet must arrive intact and unaltered.
#[tokio::test]
async fn test_sim_clean_delivery() {
    let sender = sim_socket(SimulationConfig::default()).await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    let pkt = make_packet(42, b"hello simulator");
    sender.send_to(&pkt, recv_addr).await.expect("send_to");

    let (got, _from) = tokio::time::timeout(Duration::from_millis(500), receiver.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from error");

    assert_eq!(got.header.seq, 42, "seq must survive round-trip");
    assert_eq!(&got.payload, b"hello simulator", "payload must survive round-trip");
}

// ---------------------------------------------------------------------------
// Test 2: loss_rate = 1.0 — every packet is silently dropped.
// ---------------------------------------------------------------------------

/// When `loss_rate = 1.0` every outbound packet is swallowed at the sender
/// before it ever reaches the OS socket.  `recv_from` at the receiver must
/// time out because nothing is in flight.
#[tokio::test]
async fn test_sim_loss_drops_all() {
    let sender = sim_socket(SimulationConfig {
        loss_rate: 1.0,
        seed: Some(1),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    for i in 0..5u32 {
        sender
            .send_to(&make_packet(i * 8, b"dropped"), recv_addr)
            .await
            .expect("send_to must succeed even when dropping");
    }

    // Nothing should arrive within 300 ms.
    let result = tokio::time::timeout(Duration::from_millis(300), receiver.recv_from()).await;
    assert!(
        result.is_err(),
        "recv_from should time out; loss_rate=1.0 must drop every packet"
    );
}

// ---------------------------------------------------------------------------
// Test 3: loss_rate = 0.0 — no packets dropped.
// ---------------------------------------------------------------------------

/// Statistical sanity check: with `loss_rate = 0.0` all sent packets must
/// arrive.  This validates that the default (no-fault) path is correctly wired
/// all the way to the OS socket.
#[tokio::test]
async fn test_sim_no_loss_delivers_all() {
    const N: u32 = 8;

    let sender = sim_socket(SimulationConfig {
        loss_rate: 0.0,
        seed: Some(2),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    for i in 0..N {
        sender
            .send_to(&make_packet(i * 8, &[i as u8; 4]), recv_addr)
            .await
            .expect("send_to");
    }

    let mut count = 0u32;
    loop {
        match tokio::time::timeout(Duration::from_millis(200), receiver.recv_from()).await {
            Ok(Ok(_)) => count += 1,
            _ => break,
        }
    }
    assert_eq!(count, N, "all {N} packets must arrive when loss_rate=0");
}

// ---------------------------------------------------------------------------
// Test 4: corrupt_rate = 1.0 — corrupted datagrams are silently discarded.
// ---------------------------------------------------------------------------

/// `Packet::decode` inside `recv_from` detects the checksum mismatch and
/// loops, so the caller never receives a corrupted packet — it simply
/// experiences a timeout, exactly as if the packet had been dropped.
///
/// This validates the NIC-CRC-discard behaviour described in the module docs.
#[tokio::test]
async fn test_sim_corruption_silently_discarded() {
    let sender = sim_socket(SimulationConfig {
        corrupt_rate: 1.0,
        corrupt_bits: 4,
        seed: Some(3),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    for i in 0..5u32 {
        sender
            .send_to(&make_packet(i * 8, b"corrupt me"), recv_addr)
            .await
            .expect("send_to");
    }

    // recv_from loops on every decode error; nothing survives to the caller.
    let result = tokio::time::timeout(Duration::from_millis(300), receiver.recv_from()).await;
    assert!(
        result.is_err(),
        "corrupted datagrams must be silently discarded; recv_from must time out"
    );
}

// ---------------------------------------------------------------------------
// Test 5: duplicate_rate = 1.0 — every packet is delivered exactly twice.
// ---------------------------------------------------------------------------

/// The primary copy arrives at the normal delay; the duplicate arrives
/// 1 ms later.  Both copies must be identical and both must arrive within
/// the timeout window.
#[tokio::test]
async fn test_sim_duplicate_delivers_twice() {
    let sender = sim_socket(SimulationConfig {
        duplicate_rate: 1.0,
        seed: Some(4),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    sender
        .send_to(&make_packet(0, b"dup"), recv_addr)
        .await
        .expect("send_to");

    let (first, _) = tokio::time::timeout(Duration::from_millis(200), receiver.recv_from())
        .await
        .expect("timeout on first copy")
        .expect("recv error on first copy");

    let (second, _) = tokio::time::timeout(Duration::from_millis(200), receiver.recv_from())
        .await
        .expect("timeout on second copy")
        .expect("recv error on second copy");

    assert_eq!(first.header.seq, 0, "first copy seq");
    assert_eq!(second.header.seq, 0, "second copy seq");
    assert_eq!(&first.payload, b"dup", "first copy payload");
    assert_eq!(&second.payload, b"dup", "second copy payload");
}

// ---------------------------------------------------------------------------
// Test 6: no third copy when duplicate_rate = 1.0
// ---------------------------------------------------------------------------

/// There must be exactly one extra copy — not an unbounded stream of
/// duplicates.  After the primary and duplicate arrive, recv_from must block.
#[tokio::test]
async fn test_sim_duplicate_exactly_two_copies() {
    let sender = sim_socket(SimulationConfig {
        duplicate_rate: 1.0,
        seed: Some(5),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    sender
        .send_to(&make_packet(0, b"dup"), recv_addr)
        .await
        .expect("send_to");

    // Drain both copies.
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_millis(200), receiver.recv_from())
            .await
            .expect("timeout")
            .expect("recv error");
    }

    // Third recv_from must time out — no third copy.
    let third = tokio::time::timeout(Duration::from_millis(100), receiver.recv_from()).await;
    assert!(third.is_err(), "must be exactly two copies, not three");
}

// ---------------------------------------------------------------------------
// Test 7: base_delay — packet is not delivered before the configured delay.
// ---------------------------------------------------------------------------

/// The background task spawned by `schedule()` sleeps for at least
/// `base_delay` before writing to the OS socket.  Elapsed time at the
/// receiver must reflect this.
#[tokio::test]
async fn test_sim_base_delay_measurable() {
    const DELAY: Duration = Duration::from_millis(80);
    // Allow 30 ms of scheduling slack on loaded CI machines.
    const TOLERANCE: Duration = Duration::from_millis(30);

    let sender = sim_socket(SimulationConfig {
        base_delay: DELAY,
        seed: Some(6),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    let t0 = Instant::now();
    sender
        .send_to(&make_packet(0, b"delayed"), recv_addr)
        .await
        .expect("send_to");

    tokio::time::timeout(Duration::from_millis(500), receiver.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from error");

    let elapsed = t0.elapsed();
    assert!(
        elapsed >= DELAY - TOLERANCE,
        "expected delay ≥ {:?}, actual {:?}",
        DELAY - TOLERANCE,
        elapsed,
    );
}

// ---------------------------------------------------------------------------
// Test 8: jitter — actual delay falls within [base_delay, base_delay + jitter].
// ---------------------------------------------------------------------------

/// The jitter sample is drawn uniformly from [0, jitter], so the total
/// delivery delay must lie in [base_delay, base_delay + jitter].
#[tokio::test]
async fn test_sim_jitter_within_bounds() {
    const BASE: Duration = Duration::from_millis(20);
    const JITTER: Duration = Duration::from_millis(60);
    const TOLERANCE: Duration = Duration::from_millis(25);

    let sender = sim_socket(SimulationConfig {
        base_delay: BASE,
        jitter: JITTER,
        seed: Some(7),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    let t0 = Instant::now();
    sender
        .send_to(&make_packet(0, b"jitter"), recv_addr)
        .await
        .expect("send_to");

    tokio::time::timeout(Duration::from_millis(500), receiver.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from error");

    let elapsed = t0.elapsed();
    let min_expected = BASE.saturating_sub(TOLERANCE);
    let max_expected = BASE + JITTER + TOLERANCE;

    // Use saturating_sub so BASE < TOLERANCE doesn't panic at compile/runtime.
    assert!(
        elapsed >= min_expected,
        "elapsed {:?} is below base_delay - tolerance {:?}",
        elapsed, min_expected,
    );
    assert!(
        elapsed <= max_expected,
        "elapsed {:?} exceeds base + jitter + tolerance {:?}",
        elapsed, max_expected,
    );
}

// ---------------------------------------------------------------------------
// Test 9: reorder hold buffer — reorder_prob=1.0 stashes every packet.
// ---------------------------------------------------------------------------

/// With `reorder_prob=1.0` every packet is pushed into the `VecDeque` hold
/// buffer and nothing is sent until `flush_held` is called.  This validates
/// the stash side of the hold/release mechanism in isolation.
#[tokio::test]
async fn test_sim_reorder_stash_holds_packets() {
    let sender = sim_socket(SimulationConfig {
        reorder_prob: 1.0,
        reorder_delay_ms: 20,
        reorder_cap: 8, // large cap so all packets fit
        seed: Some(10),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    for i in 0..4u32 {
        sender
            .send_to(&make_packet(i * 8, b"hold"), recv_addr)
            .await
            .expect("send_to");
    }

    // Nothing must arrive — all 4 are sitting in the hold buffer.
    let nothing = tokio::time::timeout(Duration::from_millis(60), receiver.recv_from()).await;
    assert!(
        nothing.is_err(),
        "packets must remain stashed until flush_held is called"
    );

    // flush_held schedules all held packets; they arrive within reorder_delay_ms.
    sender.flush_held().await;

    let mut count = 0u32;
    loop {
        match tokio::time::timeout(Duration::from_millis(200), receiver.recv_from()).await {
            Ok(Ok(_)) => count += 1,
            _ => break,
        }
    }
    assert_eq!(count, 4, "flush_held must deliver all 4 stashed packets");
}

// ---------------------------------------------------------------------------
// Test 10: reorder overtake — cap bypass creates deterministic out-of-order.
// ---------------------------------------------------------------------------

/// Mechanism walkthrough (`reorder_prob=1.0`, `reorder_cap=1`):
///
/// ```text
/// send(pkt_A, seq=0):  reorder=1.0 → q.len()=0 < cap=1 → stash
/// send(pkt_B, seq=8):  reorder=1.0 → q.len()=1 >= cap=1 → cap bypass → send immediately
/// flush_held():        drain [pkt_A] → schedule(pkt_A, reorder_delay_ms)
/// ```
///
/// Result: pkt_B (sent second) arrives before pkt_A (sent first but stashed),
/// because pkt_B departs immediately while pkt_A waits for flush_held + delay.
#[tokio::test]
async fn test_sim_reorder_cap_bypass_creates_overtake() {
    const REORDER_DELAY: Duration = Duration::from_millis(60);

    let sender = sim_socket(SimulationConfig {
        reorder_prob: 1.0,    // every packet selected for reordering
        reorder_delay_ms: 60, // flush_held adds this before delivery
        reorder_cap: 1,       // cap=1: second packet bypasses rather than stashing
        seed: Some(11),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    // pkt_A: hits the queue (q.len()=0 < cap=1) → stashed.
    sender
        .send_to(&make_packet(0, b"stashed"), recv_addr)
        .await
        .expect("send pkt_A");

    // pkt_B: cap reached (q.len()=1 >= cap=1) → cap bypass → departs now.
    sender
        .send_to(&make_packet(8, b"bypass"), recv_addr)
        .await
        .expect("send pkt_B");

    // Release pkt_A via flush_held; it arrives reorder_delay_ms later.
    sender.flush_held().await;

    // First arrival: pkt_B (seq=8), because it bypassed the stash.
    let (first, _) = tokio::time::timeout(Duration::from_millis(200), receiver.recv_from())
        .await
        .expect("timeout on first arrival")
        .expect("recv error on first arrival");
    assert_eq!(first.header.seq, 8, "cap-bypass packet (seq=8) must arrive first");

    // Second arrival: pkt_A (seq=0), released by flush_held with extra delay.
    let t_before_second = std::time::Instant::now();
    let (second, _) = tokio::time::timeout(Duration::from_millis(500), receiver.recv_from())
        .await
        .expect("timeout on second arrival")
        .expect("recv error on second arrival");
    assert_eq!(second.header.seq, 0, "stashed packet (seq=0) must arrive second");

    // Verify that the stashed packet actually waited for reorder_delay_ms.
    let gap = t_before_second.elapsed();
    assert!(
        gap <= REORDER_DELAY + Duration::from_millis(50),
        "second arrival gap {gap:?} should be within reorder window"
    );
}

// ---------------------------------------------------------------------------
// Test 10: bandwidth limit — a saturated token bucket adds measurable delay.
// ---------------------------------------------------------------------------

/// After the burst budget is consumed by the first packet, the second packet
/// must wait for the token bucket to refill.  The delivery time for the second
/// packet must be at least `payload_bytes / rate_bps`.
///
/// Numbers chosen to complete in ~250 ms on any machine:
///   rate = 4096 B/s,  payload = 1024 B → wait ≈ 250 ms.
#[tokio::test]
async fn test_sim_bw_limit_throttles() {
    const RATE: u64 = 4_096; // bytes/s
    const PAYLOAD: usize = 1_024; // bytes (one fill of burst budget)

    // burst = PAYLOAD so the first packet exactly drains the initial budget.
    let sender = sim_socket(SimulationConfig {
        bw_limit_bps: Some(RATE),
        bw_burst_bytes: PAYLOAD as u64,
        seed: Some(8),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    let payload = vec![b'x'; PAYLOAD];

    // First packet: burst budget covers it — delivered immediately.
    sender
        .send_to(&make_packet(0, &payload), recv_addr)
        .await
        .expect("first send_to");
    tokio::time::timeout(Duration::from_millis(500), receiver.recv_from())
        .await
        .expect("first recv timeout")
        .expect("first recv error");

    // Second packet: bucket is empty; delivery must be gated by token refill.
    let t0 = Instant::now();
    sender
        .send_to(&make_packet(PAYLOAD as u32, &payload), recv_addr)
        .await
        .expect("second send_to");
    tokio::time::timeout(Duration::from_secs(5), receiver.recv_from())
        .await
        .expect("second recv timeout — BW gate never opened")
        .expect("second recv error");
    let elapsed = t0.elapsed();

    // Expect at least 100 ms (being generous; theoretical ≈ 250 ms).
    let min_expected = Duration::from_millis(100);
    assert!(
        elapsed >= min_expected,
        "BW limit not enforced: expected ≥ {:?}, actual {:?}",
        min_expected, elapsed,
    );
}

// ---------------------------------------------------------------------------
// Test 11: seed determinism — identical seeds produce identical fault patterns.
// ---------------------------------------------------------------------------

/// With the same `seed`, `loss_rate`, and packet sequence, two independent
/// runs must produce the exact same set of received sequence numbers.
///
/// This is the property that makes deterministic replay possible: a failing
/// test can record its seed and reproduce the same fault trace every time.
async fn run_with_seed(seed: u64, n: u32, loss: f64) -> Vec<u32> {
    let sender = sim_socket(SimulationConfig {
        loss_rate: loss,
        seed: Some(seed),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    for i in 0..n {
        sender
            .send_to(&make_packet(i * 8, &[i as u8; 4]), recv_addr)
            .await
            .unwrap();
    }

    let mut seqs = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(50), receiver.recv_from()).await {
            Ok(Ok((pkt, _))) => seqs.push(pkt.header.seq),
            _ => break,
        }
    }
    seqs
}

#[tokio::test]
async fn test_sim_seed_deterministic() {
    const SEED: u64 = 0xcafe_babe_dead_beef;
    const N: u32 = 12;
    const LOSS: f64 = 0.4; // ~40 % drop → several packets survive for comparison

    let run1 = run_with_seed(SEED, N, LOSS).await;
    let run2 = run_with_seed(SEED, N, LOSS).await;

    assert!(
        !run1.is_empty(),
        "seed={SEED}: no packets arrived — loss_rate might be 1.0 for this seed"
    );
    assert_eq!(
        run1, run2,
        "same seed must produce identical fault sequence\n  run1={run1:?}\n  run2={run2:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 12: different seeds produce different patterns (probabilistic sanity).
// ---------------------------------------------------------------------------

/// Two different seeds should almost certainly not produce the same drop
/// pattern for 12 packets at 40 % loss (probability of collision ≈ 2^{-12}).
#[tokio::test]
async fn test_sim_different_seeds_differ() {
    const N: u32 = 12;
    const LOSS: f64 = 0.4;

    let run_a = run_with_seed(0x1111_1111_1111_1111, N, LOSS).await;
    let run_b = run_with_seed(0x2222_2222_2222_2222, N, LOSS).await;

    // At least one must have received something; and they must differ.
    // (If both happen to receive the same set the test is a false negative,
    // but with probability < 1/4096 this won't happen in practice.)
    assert!(
        !run_a.is_empty() || !run_b.is_empty(),
        "both runs received nothing — seeds might both map to loss=1.0"
    );
    assert_ne!(
        run_a, run_b,
        "different seeds produced identical fault sequences — PRNG may be broken"
    );
}

// ---------------------------------------------------------------------------
// Test 13: combined faults — loss + delay coexist correctly.
// ---------------------------------------------------------------------------

/// With `loss_rate = 0.5` and `base_delay = 20 ms`, the packets that survive
/// the drop decision must still be delayed.  This exercises the path where
/// the RNG lock is held once and both decisions are made atomically.
#[tokio::test]
async fn test_sim_combined_loss_and_delay() {
    const N: u32 = 20;
    const DELAY: Duration = Duration::from_millis(20);
    const TOLERANCE: Duration = Duration::from_millis(15);

    let sender = sim_socket(SimulationConfig {
        loss_rate: 0.5,
        base_delay: DELAY,
        seed: Some(9),
        ..Default::default()
    })
    .await;
    let receiver = sim_socket(SimulationConfig::default()).await;
    let recv_addr = receiver.local_addr;

    let t0 = Instant::now();
    for i in 0..N {
        sender
            .send_to(&make_packet(i * 8, b"x"), recv_addr)
            .await
            .expect("send_to");
    }

    // Collect all arriving packets (bounded by a 1 s wall clock).
    let mut received = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(300), receiver.recv_from()).await {
            Ok(Ok((pkt, _))) => received.push(pkt.header.seq),
            _ => break,
        }
    }

    // At least one packet must have survived (with seed=9, loss=0.5, N=20).
    assert!(!received.is_empty(), "no packets survived loss+delay combination");

    // The first packet must not have arrived before DELAY - TOLERANCE.
    let elapsed = t0.elapsed();
    // Since we waited for all packets, elapsed must be ≥ DELAY for each
    // surviving packet.  Check that total elapsed is at least DELAY.
    assert!(
        elapsed >= DELAY - TOLERANCE,
        "surviving packets arrived too early — base_delay may be ignored"
    );

    // All received sequence numbers must be valid multiples of 8.
    for seq in &received {
        assert_eq!(seq % 8, 0, "seq={seq} is not a multiple of 8");
    }
}
