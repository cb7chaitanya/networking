//! Async UDP socket abstraction.
//!
//! This module provides [`Socket`], a thin wrapper around `tokio::net::UdpSocket`
//! that speaks [`crate::packet::Packet`] instead of raw bytes.  Its
//! responsibilities are strictly I/O:
//! - Binding / connecting the underlying UDP socket.
//! - Encoding a [`crate::packet::Packet`] and writing one datagram.
//! - Reading one datagram and decoding it into a [`crate::packet::Packet`].
//! - Surfacing I/O errors without interpreting protocol semantics.
//!
//! All protocol logic (sequencing, windowing, retransmits) lives in other
//! modules.  [`Socket`] knows only how to move bytes between the OS and the
//! packet layer.

use std::net::SocketAddr;

use crate::packet::{Packet, PacketError};

/// Errors that can arise from socket operations.
#[derive(Debug)]
pub enum SocketError {
    /// Underlying I/O error from the OS.
    Io(std::io::Error),
    /// The received datagram could not be decoded as a valid packet.
    Packet(PacketError),
}

impl From<std::io::Error> for SocketError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PacketError> for SocketError {
    fn from(e: PacketError) -> Self {
        Self::Packet(e)
    }
}

/// An async, packet-oriented UDP socket.
///
/// TODO: store `tokio::net::UdpSocket` and a scratch buffer for recv.
pub struct Socket {
    /// Address this socket is bound to.
    pub local_addr: SocketAddr,
}

impl Socket {
    /// Bind a new socket to `local_addr`.
    ///
    /// TODO: call `tokio::net::UdpSocket::bind(local_addr)`.
    pub async fn bind(_local_addr: SocketAddr) -> Result<Self, SocketError> {
        todo!("bind UDP socket")
    }

    /// Send `packet` to `dest`.
    ///
    /// Encodes the packet via [`Packet::encode`] and writes one datagram.
    ///
    /// TODO: call `socket.send_to(&encoded, dest)`.
    pub async fn send_to(
        &self,
        _packet: &Packet,
        _dest: SocketAddr,
    ) -> Result<(), SocketError> {
        todo!("encode and send datagram")
    }

    /// Wait for the next datagram and decode it.
    ///
    /// Returns the decoded [`Packet`] and the sender's address.
    ///
    /// TODO: call `socket.recv_from(&mut buf)`, then `Packet::decode`.
    pub async fn recv_from(&self) -> Result<(Packet, SocketAddr), SocketError> {
        todo!("recv datagram and decode")
    }
}
