//! Per-connection lifecycle manager.
//!
//! A [`Connection`] owns the complete state for one logical peer-to-peer
//! session.  Its responsibilities are:
//! - Driving the finite-state machine (see [`crate::state`]).
//! - Coordinating [`crate::sender`] and [`crate::receiver`].
//! - Dispatching inbound [`crate::packet::Packet`]s to the right handler.
//! - Scheduling retransmit events via [`crate::timer`].
//! - Exposing an async read/write API to application code.
//!
//! Connection objects are created either by an active open (client side) or
//! by accepting a peer's SYN (server side).  Both paths will be represented
//! here once the handshake module is implemented.

use crate::{
    receiver::Receiver,
    sender::Sender,
    socket::Socket,
    state::ConnectionState,
    timer::TimerHandle,
};

/// A handle to a single reliable connection over UDP.
///
/// TODO: add sequence-number tracking fields (ISN, SND.NXT, SND.UNA, RCV.NXT).
pub struct Connection {
    /// Current FSM state.
    pub state: ConnectionState,
    /// Outbound segment manager.
    pub sender: Sender,
    /// Inbound reassembly buffer.
    pub receiver: Receiver,
    /// Underlying datagram socket.
    pub socket: Socket,
    /// Active retransmit / keep-alive timer.
    pub timer: TimerHandle,
}

impl Connection {
    /// Create a new connection in the initial [`ConnectionState::Closed`] state.
    ///
    /// TODO: accept remote [`std::net::SocketAddr`] and initial sequence numbers.
    pub fn new(_socket: Socket) -> Self {
        todo!("construct Connection")
    }

    /// Initiate an active open (client side).
    ///
    /// TODO: send SYN, transition to SynSent, await SYN-ACK.
    pub async fn connect(&mut self) {
        todo!("active open / send SYN")
    }

    /// Process one inbound packet received from the socket.
    ///
    /// TODO: dispatch to sender/receiver based on flags and current FSM state.
    pub async fn handle_packet(&mut self, _packet: crate::packet::Packet) {
        todo!("demux inbound packet")
    }

    /// Write application data into the send buffer.
    ///
    /// TODO: segment data, assign sequence numbers, hand to Sender.
    pub async fn write(&mut self, _data: &[u8]) {
        todo!("buffer outbound application data")
    }

    /// Read received application data into `buf`.
    ///
    /// TODO: drain from Receiver's reassembly buffer.
    pub async fn read(&mut self, _buf: &mut [u8]) -> usize {
        todo!("drain inbound application data")
    }

    /// Initiate a graceful close (send FIN).
    ///
    /// TODO: transition FSM through FinWait1 → FinWait2 → TimeWait.
    pub async fn close(&mut self) {
        todo!("send FIN and drain")
    }
}
