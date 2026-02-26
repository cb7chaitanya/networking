//! `tcp-over-udp` — a TCP-like reliable byte stream implemented over UDP.
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────┐   segments   ┌──────────┐
//!  │  Sender  │─────────────▶│ Receiver │
//!  └────┬─────┘              └─────┬────┘
//!       │                          │
//!       │        ACKs              │
//!       │◀─────────────────────────┘
//!       │
//!  ┌────▼──────────────────────────────┐
//!  │           Connection              │
//!  │  (owns state machine + socket)    │
//!  └────┬──────────────────────────────┘
//!       │ raw UDP datagrams
//!  ┌────▼──────┐
//!  │  Socket   │  (thin async wrapper around tokio UdpSocket)
//!  └───────────┘
//! ```
//!
//! Each module has a single responsibility:
//! - [`packet`]     — wire format (serialise / deserialise)
//! - [`connection`] — per-connection lifecycle
//! - [`state`]      — finite-state-machine types
//! - [`sender`]     — outbound segment logic and retransmit queue
//! - [`receiver`]   — inbound segment reassembly
//! - [`timer`]      — retransmit and keep-alive timers
//! - [`simulator`]  — optional lossy/reorder network layer for testing
//! - [`socket`]     — async UDP socket abstraction

pub mod connection;
pub mod packet;
pub mod receiver;
pub mod sender;
pub mod simulator;
pub mod socket;
pub mod state;
pub mod timer;
