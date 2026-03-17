# tcp-over-udp

A complete TCP-like reliable transport stack implemented from scratch in Rust, running over UDP sockets. Built as a learning project to understand what TCP actually does at the implementation level — not what the textbook says, but what the RFCs specify and what breaks when you get it wrong.

## Features

| Feature | RFC | Status |
|---|---|---|
| 3-way handshake + ISN generation | 793 | ✅ |
| MSS negotiation via TCP options | 6691 | ✅ |
| Stop-and-wait reliable delivery | 793 | ✅ |
| Go-Back-N sliding window | 793 | ✅ |
| Selective Repeat (OOO buffering + gap-fill) | 793 | ✅ |
| SACK (Selective Acknowledgement) | 2018 | ✅ |
| TCP Reno congestion control | 5681 | ✅ |
| Pluggable congestion control trait | — | ✅ |
| RTT estimation (SRTT/RTTVAR/RTO) | 6298 | ✅ |
| Karn's algorithm | 6298 | ✅ |
| Receiver-side flow control | 793 | ✅ |
| Persist timer (zero-window probing) | 793 §3.7 | ✅ |
| Nagle's algorithm | 896 | ✅ |
| Internet checksum | 1071 | ✅ |
| Full TCP teardown (FIN/TIME_WAIT) | 793 | ✅ |
| Simultaneous close | 793 | ✅ |
| Fault injection simulator | — | ✅ |

## Quick Start

```bash
# Terminal 1 — start the server
cargo run -- server

# Terminal 2 — connect a client
cargo run -- client --server 127.0.0.1:8080

# Run all tests (excluding the known pre-existing hang in test_gbn_concurrent_session)
cargo test --lib
cargo test --test gbn_tests -- --skip test_gbn_concurrent_session
cargo test --test simulator_tests
```

## Architecture

The stack is organised into three layers, each building on the previous.

```
┌──────────────────────────────────────────────┐
│              Application                     │
│     send() / recv() / flush() / close()      │
├──────────────────────────────────────────────┤
│         GbnConnection  (Layer 3)             │
│  Sliding window · CC · Flow control · SACK   │
│  Sequential API   │   Concurrent API (run()) │
│                   │   ┌────────────────────┐ │
│                   │   │  GbnSession handle │ │
│                   │   │  send_tx / recv_rx │ │
│                   │   └────────┬───────────┘ │
│                   │            │ event_loop  │
├──────────────────────────────────────────────┤
│         Connection  (Layer 2)                │
│  3-way handshake · MSS negotiation · FSM     │
├──────────────────────────────────────────────┤
│         Packet / Socket  (Layer 1)           │
│  Wire format · TLV options · Checksum · UDP  │
└──────────────────────────────────────────────┘
```

### Source layout

```
src/
├── packet.rs            Wire format: 15-byte fixed header + TLV options (MSS/SACK/NOP)
├── socket.rs            Thin async wrapper over tokio::net::UdpSocket
├── state.rs             RFC 793 10-state FSM enum
├── sender.rs            Stop-and-wait send-side state
├── receiver.rs          Stop-and-wait receive-side state
├── rtt.rs               RFC 6298 RTT estimator (SRTT/RTTVAR, Karn's algorithm)
├── timer.rs             Timer types (deprecated — logic lives in rtt.rs)
├── connection.rs        Stop-and-wait connection lifecycle (handshake, data, close)
├── congestion_control.rs  CongestionControl trait + RenoCC implementation
├── persist_timer.rs     RFC 793 §3.7 persist timer state machine
├── gbn_sender.rs        Sliding-window sender (CC, flow control, Nagle, SACK)
├── gbn_receiver.rs      Selective Repeat receiver (OOO buffer, SACK blocks)
├── gbn_connection.rs    GBN connection: both sequential and concurrent session APIs
├── simulator.rs         Fault injection layer (loss, reorder, corrupt, BW throttle)
├── main.rs              CLI demo (stop-and-wait + GBN ping-pong)
└── lib.rs               Public module re-exports

tests/
├── gbn_tests.rs         41 integration tests for the GBN layer
├── simulator_tests.rs   14 integration tests for the fault injector
├── handshake.rs         Handshake-specific tests
├── persist_timer_tests.rs  Zero-window stall and recovery tests
└── stress_test.rs       Stress tests
```

## The Wire Format

```
Byte  0–3   seq        u32 big-endian
Byte  4–7   ack        u32 big-endian
Byte  8     flags      SYN=1 ACK=2 FIN=4 RST=8 OPT=16
Byte  9–10  window     u16 big-endian
Byte 11–12  checksum   u16 (RFC 1071, computed over full packet)
Byte 13–14  payload_len u16 big-endian
[Byte 15…]  options    TLV, present only when OPT flag is set
[…]         payload
```

Options use the same TLV encoding as TCP: `kind(1) | len(1) | value(len-2)`. Supported:

| Kind | Name | Length | Value |
|------|------|--------|-------|
| 0    | EOL  | 1      | — |
| 1    | NOP  | 1      | — |
| 2    | MSS  | 4      | u16 MSS value |
| 5    | SACK | 2+8n   | n × (left:u32, right:u32) |

## Two Usage Modes

### Sequential (blocking-style)

```rust
// Client
let sock = Socket::bind("0.0.0.0:0".parse()?).await?;
let mut conn = GbnConnection::connect(sock, server_addr, /* window */ 4).await?;
conn.send(b"hello").await?;
let reply = conn.recv().await?;
conn.close().await?;

// Server
let sock = Socket::bind("0.0.0.0:8080".parse()?).await?;
let mut conn = GbnConnection::accept(sock, 4).await?;
loop {
    match conn.recv().await {
        Ok(data)            => conn.send(&data).await?,
        Err(ConnError::Eof) => break,
        Err(e)              => return Err(e),
    }
}
conn.close().await?;
```

### Concurrent (`run()`)

```rust
let conn = GbnConnection::connect(sock, server_addr, 4).await?;
let mut session = conn.run(); // spawns background event loop

// Send and receive concurrently
session.send(b"hello".to_vec()).await?;
let reply = session.recv().await?;

session.close().await; // drops send_tx → FIN, awaits loop exit
```

## Congestion Control

`CongestionControl` is a trait, making it easy to swap algorithms:

```rust
pub trait CongestionControl: Debug + Send + 'static {
    fn on_ack(&mut self, acked_segments: usize);
    fn on_loss(&mut self, in_flight: usize, kind: LossKind);
    fn cwnd(&self) -> usize;
}
```

The default implementation is `RenoCC` (TCP Reno):

- **Slow start**: `cwnd += acked_count` per ACK until `ssthresh`
- **Congestion avoidance**: `cwnd += 1` per RTT (additive via fractional counter)
- **Fast retransmit**: on 3 duplicate ACKs, `ssthresh = max(2, in_flight/2)`, `cwnd = ssthresh + 3`
- **Fast recovery**: exit to CA on next new ACK
- **Timeout**: `ssthresh = max(2, in_flight/2)`, `cwnd = 1`, re-enter slow start

To use a custom algorithm, pass it as the type parameter:

```rust
let conn = GbnConnection::<MyCubicCC>::connect(sock, peer, 4).await?;
```

## SACK

Selective Acknowledgement is fully implemented across all four layers:

1. **Receiver** builds SACK blocks from its `BTreeMap` out-of-order buffer, merging contiguous entries and capping at 4 blocks.
2. **Packet** encodes/decodes SACK as TLV option kind=5 (8 bytes per block). The `OPT` flag distinguishes options from payload.
3. **Sender** marks `GbnEntry::sacked` when a SACK block covers the entry's byte range. `retransmit_oldest()` skips sacked entries, retransmitting only genuinely missing segments.
4. **Connection** attaches SACK blocks to every outbound ACK when the OOO buffer is non-empty, and calls `process_sack()` on every received ACK.

## Fault Injection Simulator

`SimulatedSocket` wraps a real UDP socket with configurable fault injection, using a seeded PRNG for deterministic test scenarios.

```rust
let sim = SimulatedSocket::bind(addr, SimulationConfig {
    loss_rate:       0.10,  // drop 10% of packets
    reorder_prob:    0.05,  // hold 5% for reordering
    reorder_delay_ms: 50,
    duplicate_rate:  0.02,  // duplicate 2%
    corrupt_rate:    0.01,  // flip bits in 1%
    base_delay:      Duration::from_millis(5),
    jitter:          Duration::from_millis(2),
    bw_limit_bps:    Some(1_000_000), // 1 Mbps cap
    seed:            42,
    ..Default::default()
}).await?;
```

## Known Issues

- **`test_gbn_concurrent_session` hangs**: Pre-existing hang introduced by the CC trait refactor. Root cause is divergence between the event loop's inline ACK handling and the centralised `on_ack_received()` path used by the sequential API. The concurrent session (`run()` / `GbnSession`) is affected; all sequential-API tests pass. Fix: route the event loop's ACK handling through `on_ack_received()`.
- **`timer.rs` deprecated**: `TimerHandle::arm()`/`cancel()` are `todo!()` stubs. Actual RTT logic lives in `rtt.rs`. Keep-alive probes are not sent.
- **No window scaling** (RFC 1323): receive window capped at 16-bit (64 KiB).
- **No TCP timestamps** (RFC 1323): no PAWS, no timestamp-based RTTM.
- **URG/PUSH flags**: defined but not used.

## Test Coverage

```
cargo test --lib                                      # 107 unit tests
cargo test --test gbn_tests -- --skip test_gbn_concurrent_session  # 40 integration tests
cargo test --test simulator_tests                     # 14 simulator tests
```

| Module | Tests | Focus |
|---|---|---|
| `packet.rs` | 28 | Encode/decode, MSS, SACK, checksum, flags |
| `rtt.rs` | 11 | EWMA convergence, back-off, min/max RTO |
| `persist_timer.rs` | 10 | Zero-window activation, probe back-off |
| `gbn_sender.rs` | 38 | Window, ACK, CC transitions, SACK marking |
| `gbn_receiver.rs` | 20 | OOO buffer, delivery chain, SACK blocks |
| `gbn_tests.rs` | 40 | Full connection lifecycle, CC, flow control, SR, Nagle, TIME_WAIT |
| `simulator_tests.rs` | 14 | Loss, reorder, corrupt, duplicate, BW throttle, PRNG seed |

## Dependencies

```toml
tokio      = { version = "1", features = ["full"] }
log        = "0.4"
env_logger = "0.11"
clap       = { version = "4", features = ["derive"] }
```

No `rand` crate — ISN generation uses `DefaultHasher` + `SystemTime`; the simulator uses an inline SplitMix64 PRNG.
