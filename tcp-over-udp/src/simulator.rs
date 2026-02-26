//! Optional network simulator for deterministic testing.
//!
//! Real networks drop, reorder, and duplicate packets.  To exercise the
//! reliability mechanisms without depending on actual network conditions,
//! this module provides a [`Simulator`] that wraps a [`crate::socket::Socket`]
//! and intercepts sends and receives, applying a configurable fault model:
//!
//! | Fault            | Description                                      |
//! |------------------|--------------------------------------------------|
//! | Packet loss      | Drop a packet with probability `loss_rate`.      |
//! | Reordering       | Delay a packet by `reorder_delay`, letting later |
//! |                  | packets overtake it.                             |
//! | Duplication      | Deliver a packet twice.                          |
//! | Corruption       | Flip random bits in the payload.                 |
//! | Bandwidth cap    | Rate-limit throughput to `bw_limit` bytes/sec.   |
//!
//! The simulator is **only** compiled and used in tests; production builds
//! talk directly to the real socket layer.
//!
//! TODO: integrate with a seeded RNG so test failures are reproducible.

use std::time::Duration;

/// Configuration for the fault-injection model.
///
/// All probabilities are in the range `[0.0, 1.0]`.
#[derive(Debug, Clone)]
pub struct SimulatorConfig {
    /// Probability that any given packet is silently dropped.
    pub loss_rate: f64,
    /// Probability that a packet is reordered.
    pub reorder_rate: f64,
    /// Fixed delay applied to reordered packets.
    pub reorder_delay: Duration,
    /// Probability that a packet is duplicated.
    pub duplicate_rate: f64,
    /// Optional bandwidth cap in bytes per second (`None` = unlimited).
    pub bw_limit: Option<u64>,
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        // No faults by default — simulator is a transparent pass-through.
        Self {
            loss_rate: 0.0,
            reorder_rate: 0.0,
            reorder_delay: Duration::ZERO,
            duplicate_rate: 0.0,
            bw_limit: None,
        }
    }
}

/// A fault-injecting wrapper around the socket layer.
///
/// TODO: hold an inner `Socket`, a `SimulatorConfig`, and a pending-packet
///       queue for reordered/delayed datagrams.
pub struct Simulator {
    pub config: SimulatorConfig,
}

impl Simulator {
    /// Create a pass-through simulator (no faults).
    pub fn new(config: SimulatorConfig) -> Self {
        Self { config }
    }

    /// Send a packet through the simulated network.
    ///
    /// Applies loss, duplication, and reorder faults according to `config`
    /// before handing to the real socket.
    ///
    /// TODO: implement fault injection logic using seeded RNG.
    pub async fn send(&self, _packet: &crate::packet::Packet) {
        todo!("apply fault model then send")
    }

    /// Receive the next packet from the simulated network.
    ///
    /// May first deliver a previously reordered/delayed packet from the
    /// internal queue before reading from the real socket.
    ///
    /// TODO: drain pending queue, then poll real socket, apply duplication.
    pub async fn recv(&self) -> crate::packet::Packet {
        todo!("drain queue or recv from socket")
    }
}
