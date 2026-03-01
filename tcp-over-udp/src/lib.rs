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
//! - [`packet`]          — wire format (serialise / deserialise)
//! - [`connection`]      — stop-and-wait per-connection lifecycle
//! - [`gbn_connection`]  — Go-Back-N sliding-window connection layer
//! - [`gbn_sender`]      — GBN outbound window state machine
//! - [`gbn_receiver`]    — GBN inbound cumulative-ACK state machine
//! - [`state`]           — finite-state-machine types
//! - [`sender`]          — stop-and-wait outbound segment state
//! - [`receiver`]        — stop-and-wait inbound segment reassembly
//! - [`timer`]           — retransmit and keep-alive timers
//! - [`simulator`]       — optional lossy/reorder network layer for testing
//! - [`socket`]          — async UDP socket abstraction

pub mod connection;
pub mod gbn_connection;
pub mod gbn_receiver;
pub mod gbn_sender;
pub mod packet;
pub mod receiver;
pub mod sender;
pub mod simulator;
pub mod socket;
pub mod state;
pub mod timer;
