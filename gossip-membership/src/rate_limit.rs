/// Token-bucket rate limiter for inbound message flood protection.
///
/// Two levels of limiting:
/// - **Global**: bounds total inbound packets/sec across all peers.
/// - **Per-peer**: bounds packets/sec from any single source address.
///
/// Both use the same token-bucket algorithm: tokens refill at a fixed
/// rate up to a configurable capacity.  Each accepted packet consumes
/// one token.  When the bucket is empty, packets are dropped.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

/// Configuration for the inbound rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum tokens (burst capacity) for the global bucket.
    pub global_capacity: u32,
    /// Tokens refilled per second for the global bucket.
    pub global_refill_rate: u32,
    /// Maximum tokens (burst capacity) per peer.
    pub peer_capacity: u32,
    /// Tokens refilled per second per peer.
    pub peer_refill_rate: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_capacity: 1000,
            global_refill_rate: 500,
            peer_capacity: 100,
            peer_refill_rate: 50,
        }
    }
}

/// A single token bucket.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    capacity: u32,
    refill_rate: u32,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            tokens: capacity as f64,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token.  Refills based on elapsed time first.
    /// Returns `true` if the packet is allowed, `false` if rate-limited.
    pub fn try_consume(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens =
                (self.tokens + elapsed * self.refill_rate as f64).min(self.capacity as f64);
            self.last_refill = now;
        }
    }
}

/// Combined global + per-peer rate limiter.
pub struct InboundRateLimiter {
    global: TokenBucket,
    peers: HashMap<SocketAddr, TokenBucket>,
    peer_capacity: u32,
    peer_refill_rate: u32,
}

impl InboundRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            global: TokenBucket::new(config.global_capacity, config.global_refill_rate),
            peers: HashMap::new(),
            peer_capacity: config.peer_capacity,
            peer_refill_rate: config.peer_refill_rate,
        }
    }

    /// Check whether a packet from `from` should be accepted.
    ///
    /// Returns `true` if both the global and per-peer buckets have
    /// tokens, `false` if either is exhausted (packet should be dropped).
    pub fn allow(&mut self, from: SocketAddr, now: Instant) -> bool {
        // Check global first — cheaper than per-peer lookup.
        if !self.global.try_consume(now) {
            return false;
        }
        let peer = self
            .peers
            .entry(from)
            .or_insert_with(|| TokenBucket::new(self.peer_capacity, self.peer_refill_rate));
        if !peer.try_consume(now) {
            // Undo the global consume — this peer is throttled but the
            // global bucket shouldn't be penalised.
            self.global.tokens = (self.global.tokens + 1.0).min(self.global.capacity as f64);
            return false;
        }
        true
    }

    /// Number of tracked peers (for diagnostics).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    // ── TokenBucket tests ────────────────────────────────────────────────

    #[test]
    fn bucket_allows_up_to_capacity() {
        let mut b = TokenBucket::new(5, 10);
        let now = Instant::now();
        for _ in 0..5 {
            assert!(b.try_consume(now));
        }
        assert!(
            !b.try_consume(now),
            "should be empty after capacity consumed"
        );
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(5, 100);
        let now = Instant::now();
        // Drain all tokens.
        for _ in 0..5 {
            b.try_consume(now);
        }
        assert!(!b.try_consume(now));
        // After 50ms at 100/sec → 5 tokens refilled.
        let later = now + std::time::Duration::from_millis(50);
        assert!(b.try_consume(later));
    }

    #[test]
    fn bucket_does_not_exceed_capacity() {
        let mut b = TokenBucket::new(3, 1000);
        let later = Instant::now() + std::time::Duration::from_secs(10);
        b.refill(later);
        // Even after a long time, tokens shouldn't exceed capacity.
        assert!(b.tokens <= 3.0 + 0.001);
    }

    // ── InboundRateLimiter tests ─────────────────────────────────────────

    #[test]
    fn limiter_allows_normal_traffic() {
        let config = RateLimitConfig {
            global_capacity: 100,
            global_refill_rate: 100,
            peer_capacity: 10,
            peer_refill_rate: 10,
        };
        let mut rl = InboundRateLimiter::new(&config);
        let now = Instant::now();
        for _ in 0..10 {
            assert!(rl.allow(addr(9000), now));
        }
    }

    #[test]
    fn limiter_drops_peer_flood() {
        let config = RateLimitConfig {
            global_capacity: 1000,
            global_refill_rate: 1000,
            peer_capacity: 5,
            peer_refill_rate: 0, // no refill → strict 5-packet burst
        };
        let mut rl = InboundRateLimiter::new(&config);
        let now = Instant::now();
        let mut allowed = 0;
        for _ in 0..100 {
            if rl.allow(addr(9000), now) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5, "peer should only get 5 packets through");
    }

    #[test]
    fn limiter_drops_global_flood() {
        let config = RateLimitConfig {
            global_capacity: 10,
            global_refill_rate: 0,
            peer_capacity: 1000,
            peer_refill_rate: 1000,
        };
        let mut rl = InboundRateLimiter::new(&config);
        let now = Instant::now();
        let mut allowed = 0;
        // Multiple peers, but global is the bottleneck.
        for port in 0..100u16 {
            if rl.allow(addr(9000 + port), now) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "global limit should cap at 10");
    }

    #[test]
    fn limiter_per_peer_independent() {
        let config = RateLimitConfig {
            global_capacity: 1000,
            global_refill_rate: 1000,
            peer_capacity: 3,
            peer_refill_rate: 0,
        };
        let mut rl = InboundRateLimiter::new(&config);
        let now = Instant::now();
        // Peer A gets 3.
        for _ in 0..3 {
            assert!(rl.allow(addr(9000), now));
        }
        assert!(!rl.allow(addr(9000), now));
        // Peer B should still get its 3.
        for _ in 0..3 {
            assert!(rl.allow(addr(9001), now));
        }
        assert!(!rl.allow(addr(9001), now));
    }

    #[test]
    fn limiter_flood_1000_packets_mostly_dropped() {
        let config = RateLimitConfig {
            global_capacity: 1000,
            global_refill_rate: 0,
            peer_capacity: 20,
            peer_refill_rate: 0,
        };
        let mut rl = InboundRateLimiter::new(&config);
        let now = Instant::now();
        let mut allowed = 0;
        for _ in 0..1000 {
            if rl.allow(addr(9000), now) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 20, "only peer_capacity packets should pass");
        assert!(1000 - allowed >= 980, "most packets should be dropped");
    }

    #[test]
    fn limiter_global_undo_on_peer_reject() {
        // Verify that when a peer bucket rejects, the global token is restored.
        let config = RateLimitConfig {
            global_capacity: 100,
            global_refill_rate: 0,
            peer_capacity: 2,
            peer_refill_rate: 0,
        };
        let mut rl = InboundRateLimiter::new(&config);
        let now = Instant::now();
        // Peer A uses 2 tokens.
        assert!(rl.allow(addr(9000), now));
        assert!(rl.allow(addr(9000), now));
        // Peer A blocked → global should still have ~98 tokens.
        assert!(!rl.allow(addr(9000), now));
        // Peer B should still work (global wasn't depleted by A's rejections).
        assert!(rl.allow(addr(9001), now));
    }
}
