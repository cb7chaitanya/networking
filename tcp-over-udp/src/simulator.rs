//! Fault-injecting network simulation layer for deterministic protocol testing.
//!
//! # Architecture
//!
//! ```text
//!  Application
//!      │
//!  GbnConnection / Connection     ← protocol logic; unchanged
//!      │  send_to(packet, dest)
//!      │  recv_from()
//!      ▼
//!  SimulatedSocket                ← this module
//!      │ egress fault pipeline:
//!      │   1. drop?        → swallow, return Ok(())
//!      │   2. corrupt?     → flip bits in wire bytes
//!      │   3. reorder?     → push to VecDeque hold buffer
//!      │   4. duplicate?   → schedule a second copy
//!      │   5. BW limit?    → sleep in background task (token bucket)
//!      ▼
//!  tokio::net::UdpSocket          ← OS UDP, loopback in tests
//! ```
//!
//! All faults are injected at **egress** (`send_to`).  `recv_from` is a
//! transparent pass-through except for one thing: corrupted datagrams that
//! fail `Packet::decode` are **silently discarded** and the call loops, exactly
//! as a real NIC discards frames that fail their CRC check.  The protocol
//! layer never sees a decode error — it only sees *fewer* packets arriving,
//! which triggers the retransmit path.
//!
//! # Reordering via in-memory delay queue
//!
//! A `VecDeque` hold buffer provides explicit, deterministic reordering.
//! When a packet is selected for reordering it is **stashed** rather than
//! sent.  The next non-reordered packet releases the oldest stashed packet
//! behind itself:
//!
//! ```text
//! send_to(A)  →  [reorder]  →  held.push_back(A)             // A stashed
//! send_to(B)  →  [normal]   →  pop A → spawn(A, delay + Δ)
//!                            →          send(B, delay)         // B departs first
//!                                                              // A arrives after B
//! ```
//!
//! This coupling is **explicit** — the release of A is tied to B's departure,
//! not to wall-clock timer races.  With a seeded RNG the stash/release sequence
//! is fully deterministic regardless of the tokio scheduler.
//! `reorder_delay_ms` only needs to exceed typical OS scheduling jitter (>= 10 ms
//! on loopback) to guarantee A always arrives after B.
//!
//! ## Queue cap
//!
//! `reorder_cap` bounds memory: once the queue is full, additional packets
//! selected for reordering are let through immediately rather than dropped.
//! This prevents unbounded buffer growth if there is a long run of reordered
//! packets with no normal packets to release them.
//!
//! ## Flushing
//!
//! Call [`SimulatedSocket::flush_held`] when the sender is done to drain any
//! packets still in the hold buffer (e.g., the last segment of a stream where
//! no subsequent non-reordered packet would ever trigger a release).
//!
//! # Bandwidth limiting via token bucket
//!
//! A leaky token bucket sits between the delay gate and the actual socket
//! write.  Each token represents one byte of transmit budget.  The bucket
//! refills at `bw_limit_bps` bytes/second.
//!
//! ```text
//! background task (after sleep):
//!   tokens = min(tokens + elapsed * rate, capacity)
//!   if tokens >= packet_bytes:
//!       tokens -= packet_bytes; send immediately
//!   else:
//!       deficit = packet_bytes - tokens
//!       tokens  = 0
//!       sleep(deficit / rate)   <- this task yields; other tasks continue
//!       send
//! ```
//!
//! The sleep happens inside the spawned task, so the caller's event loop is
//! never stalled -- only the background delivery is rate-limited.  Burst
//! absorption is controlled by `bw_burst_bytes` (the bucket capacity).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::packet::Packet;
use crate::socket::SocketError;

const MAX_DATAGRAM: usize = 65_535;

// ---------------------------------------------------------------------------
// SplitMix64 PRNG
// ---------------------------------------------------------------------------

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed.wrapping_add(1) }
    }

    fn from_clock() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0xdead_beef, |d| {
                d.subsec_nanos() as u64 ^ (d.as_secs().wrapping_mul(6364136223846793005))
            });
        Self::new(nanos)
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[inline]
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0_f64 / (1u64 << 53) as f64)
    }

    #[inline]
    fn next_usize(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        (self.next_f64() * n as f64) as usize
    }
}

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate_bps: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            tokens: burst_bytes as f64,
            capacity: burst_bytes as f64,
            rate_bps: rate_bps as f64,
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self, bytes: usize) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.rate_bps).min(self.capacity);

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            Duration::ZERO
        } else {
            let deficit = bytes as f64 - self.tokens;
            self.tokens = 0.0;
            Duration::from_secs_f64(deficit / self.rate_bps)
        }
    }
}

// ---------------------------------------------------------------------------
// SimulationConfig
// ---------------------------------------------------------------------------

/// All parameters of the simulated network fault model.
///
/// Every field is independent; combine them freely.  The `Default` instance
/// represents a perfect, zero-latency, unlimited-bandwidth network.
///
/// Set `seed: Some(n)` for a deterministic fault sequence.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    // -- Loss -----------------------------------------------------------------
    /// Probability in [0, 1] that any single outbound packet is silently dropped.
    pub loss_rate: f64,

    // -- Reordering -----------------------------------------------------------
    /// Probability in [0, 1] that a packet is stashed in the hold buffer.
    ///
    /// A stashed packet is released behind the next non-stashed packet that
    /// passes through, creating an explicit overtake.
    pub reorder_prob: f64,

    /// Extra delay added when a held packet is released, in milliseconds.
    ///
    /// Must exceed OS scheduling jitter to guarantee correct delivery order.
    /// 10-50 ms is sufficient on loopback.
    pub reorder_delay_ms: u64,

    /// Maximum packets simultaneously held in the buffer.
    ///
    /// When the cap is reached, additional reordered packets bypass the hold
    /// rather than being dropped.
    pub reorder_cap: usize,

    // -- Duplication ----------------------------------------------------------
    /// Probability in [0, 1] that an outbound packet is delivered twice.
    pub duplicate_rate: f64,

    // -- Corruption -----------------------------------------------------------
    /// Probability in [0, 1] that a packet's wire bytes are corrupted.
    pub corrupt_rate: f64,

    /// Number of bits to flip per corruption event.
    pub corrupt_bits: u32,

    // -- Latency --------------------------------------------------------------
    /// Fixed propagation delay applied to every outbound packet.
    pub base_delay: Duration,

    /// Maximum additional random delay drawn uniformly from [0, jitter].
    pub jitter: Duration,

    // -- Bandwidth ------------------------------------------------------------
    /// Bytes-per-second cap on the simulated link.  `None` = unlimited.
    pub bw_limit_bps: Option<u64>,

    /// Burst size for the token bucket in bytes.  Default: 64 KiB.
    pub bw_burst_bytes: u64,

    // -- Reproducibility ------------------------------------------------------
    /// PRNG seed.  `Some(n)` = deterministic.  `None` = clock-seeded.
    pub seed: Option<u64>,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            loss_rate: 0.0,
            reorder_prob: 0.0,
            reorder_delay_ms: 20,
            reorder_cap: 4,
            duplicate_rate: 0.0,
            corrupt_rate: 0.0,
            corrupt_bits: 1,
            base_delay: Duration::ZERO,
            jitter: Duration::ZERO,
            bw_limit_bps: None,
            bw_burst_bytes: 65_536,
            seed: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SimulatedSocket
// ---------------------------------------------------------------------------

/// A fault-injecting wrapper around `tokio::net::UdpSocket`.
///
/// Presents the same `send_to` / `recv_from` interface as [`crate::socket::Socket`]
/// so it can be substituted in integration tests without modifying protocol logic.
pub struct SimulatedSocket {
    /// The underlying OS UDP socket, shared with background delay tasks.
    inner: Arc<UdpSocket>,

    /// OS-assigned local address (resolved after bind).
    pub local_addr: SocketAddr,

    config: SimulationConfig,

    /// Seeded PRNG behind a Mutex.  All random decisions for a single `send_to`
    /// are made under one lock acquisition — deterministic when seeded.
    rng: Arc<Mutex<Rng>>,

    /// Token bucket for bandwidth limiting.  `None` when `bw_limit_bps` is unset.
    token_bucket: Option<Arc<Mutex<TokenBucket>>>,

    /// Reorder hold buffer.
    ///
    /// Stashed packets are released one-by-one as non-reordered packets pass
    /// through `send_to`, creating an explicit overtake relationship.
    held: Arc<Mutex<VecDeque<(Vec<u8>, SocketAddr)>>>,
}

impl SimulatedSocket {
    /// Bind to `local_addr` and configure the fault model.
    pub async fn bind(
        local_addr: SocketAddr,
        config: SimulationConfig,
    ) -> std::io::Result<Self> {
        let inner = UdpSocket::bind(local_addr).await?;
        let local_addr = inner.local_addr()?;

        let rng = match config.seed {
            Some(s) => Rng::new(s),
            None    => Rng::from_clock(),
        };
        let token_bucket = config.bw_limit_bps.map(|rate| {
            Arc::new(Mutex::new(TokenBucket::new(rate, config.bw_burst_bytes)))
        });

        Ok(Self {
            inner: Arc::new(inner),
            local_addr,
            config,
            rng: Arc::new(Mutex::new(rng)),
            token_bucket,
            held: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    // -------------------------------------------------------------------------
    // Public interface
    // -------------------------------------------------------------------------

    /// Encode `packet` and route it through the fault pipeline toward `dest`.
    ///
    /// Returns `Ok(())` immediately.  Delayed or reordered packets are handled
    /// by background `tokio::spawn` tasks — the event loop is never blocked.
    pub async fn send_to(
        &self,
        packet: &Packet,
        dest: SocketAddr,
    ) -> Result<(), SocketError> {
        let mut bytes = packet.encode().map_err(SocketError::Packet)?;

        // All random decisions under one RNG lock acquisition.
        let (should_drop, reorder, duplicated, corrupted, jitter_frac, flip_positions) = {
            let mut rng = self.rng.lock().await;

            let should_drop = rng.next_f64() < self.config.loss_rate;
            let reorder     = rng.next_f64() < self.config.reorder_prob;
            let duplicated  = rng.next_f64() < self.config.duplicate_rate;
            let corrupted   = rng.next_f64() < self.config.corrupt_rate;
            let jitter_frac = rng.next_f64();

            let flips: Vec<(usize, u8)> = if corrupted && !bytes.is_empty() {
                (0..self.config.corrupt_bits)
                    .map(|_| (rng.next_usize(bytes.len()), 1u8 << rng.next_usize(8)))
                    .collect()
            } else {
                vec![]
            };
            (should_drop, reorder, duplicated, corrupted, jitter_frac, flips)
        };

        // 1. Drop.
        if should_drop {
            log::trace!("[sim] drop -> {dest}");
            return Ok(());
        }

        // 2. Corruption.
        if corrupted {
            for (idx, mask) in &flip_positions {
                bytes[*idx] ^= mask;
            }
            log::trace!("[sim] corrupt ({} bits) -> {dest}", self.config.corrupt_bits);
        }

        // 3. Compute normal delivery delay.
        let jitter = Duration::from_secs_f64(
            self.config.jitter.as_secs_f64() * jitter_frac,
        );
        let normal_delay = self.config.base_delay + jitter;

        // 4. Reorder path.
        //
        // Reordered packet: stash in hold buffer; a later normal packet will
        //   release it behind itself.
        //
        // Normal packet: pop the oldest held packet and dispatch it with an
        //   extra reorder_delay_ms so it arrives after the current packet.
        //   Then dispatch the current packet at normal_delay.
        //
        // The hold-queue lock is always released before any .await so no lock
        // is ever held across a yield point.
        if reorder {
            let at_cap = {
                let mut q = self.held.lock().await;
                if q.len() < self.config.reorder_cap {
                    log::trace!("[sim] hold -> {dest} (queue={})", q.len() + 1);
                    q.push_back((bytes.clone(), dest));
                    false // stashed; fall through to duplicate handling
                } else {
                    true // cap reached; lock released when q drops here
                }
            };
            if at_cap {
                // Cap reached: bypass the hold so the packet is not lost.
                log::trace!("[sim] hold-cap bypass -> {dest}");
                self.schedule(bytes.clone(), dest, normal_delay).await;
            }
        } else {
            // Release the oldest held packet behind the current one.
            let maybe_held = self.held.lock().await.pop_front();
            if let Some((h_bytes, h_dest)) = maybe_held {
                let release_delay = normal_delay
                    + Duration::from_millis(self.config.reorder_delay_ms);
                log::trace!("[sim] release held -> {h_dest} delay={release_delay:?}");
                self.schedule(h_bytes, h_dest, release_delay).await;
            }
            self.schedule(bytes.clone(), dest, normal_delay).await;
        }

        // 5. Duplicate: schedule a second copy 1 ms behind the primary.
        if duplicated {
            self.schedule(bytes, dest, normal_delay + Duration::from_millis(1)).await;
            log::trace!("[sim] dup scheduled -> {dest}");
        }

        Ok(())
    }

    /// Drain all packets still in the hold buffer, delivering each after
    /// `reorder_delay_ms`.
    ///
    /// Must be called after the last `send_to`; otherwise any packet stashed as
    /// the final send (with no subsequent normal packet to release it) would be
    /// silently discarded.
    pub async fn flush_held(&self) {
        let items: Vec<(Vec<u8>, SocketAddr)> = {
            let mut q = self.held.lock().await;
            q.drain(..).collect()
        }; // lock released before .await
        let delay = Duration::from_millis(self.config.reorder_delay_ms);
        for (bytes, dest) in items {
            self.schedule(bytes, dest, delay).await;
        }
    }

    /// Receive the next datagram, silently discarding corrupted ones.
    pub async fn recv_from(&self) -> Result<(Packet, SocketAddr), SocketError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, addr) = self.inner.recv_from(&mut buf).await?;
            match Packet::decode(&buf[..n]) {
                Ok(packet) => return Ok((packet, addr)),
                Err(e) => {
                    log::trace!("[sim] discard corrupted datagram from {addr}: {e:?}");
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helper
    // -------------------------------------------------------------------------

    /// Deliver `bytes` to `dest` after `delay` (then through the BW gate if set).
    ///
    /// Fast path (zero delay, no BW limit): sends inline via `.await`.
    /// Slow path: spawns a background task; caller returns before the sleep ends.
    async fn schedule(&self, bytes: Vec<u8>, dest: SocketAddr, delay: Duration) {
        if delay.is_zero() && self.token_bucket.is_none() {
            if let Err(e) = self.inner.send_to(&bytes, dest).await {
                log::warn!("[sim] send failed: {e}");
            }
            return;
        }

        let inner      = Arc::clone(&self.inner);
        let tb         = self.token_bucket.clone();
        let byte_count = bytes.len();

        tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if let Some(tb) = tb {
                let wait = tb.lock().await.consume(byte_count);
                if wait > Duration::ZERO {
                    tokio::time::sleep(wait).await;
                }
            }
            if let Err(e) = inner.send_to(&bytes, dest).await {
                log::warn!("[sim] background send failed: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Backwards-compatibility aliases
// ---------------------------------------------------------------------------

/// Alias preserved so existing references to `SimulatorConfig` still compile.
#[deprecated(note = "use SimulationConfig")]
pub type SimulatorConfig = SimulationConfig;

/// Thin facade preserved so existing references to `Simulator` still compile.
#[deprecated(note = "use SimulatedSocket")]
pub struct Simulator {
    pub config: SimulationConfig,
}

#[allow(deprecated)]
impl Simulator {
    pub fn new(config: SimulationConfig) -> Self {
        Self { config }
    }
}
