//! Async UDP socket abstraction.
//!
//! [`Socket`] is a thin wrapper around `tokio::net::UdpSocket` that speaks
//! [`crate::packet::Packet`] instead of raw bytes.  All protocol logic lives
//! elsewhere; this module owns only byte I/O.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::packet::{Packet, PacketError};

/// Maximum UDP payload size (theoretical limit; in practice kept much smaller).
const MAX_DATAGRAM: usize = 65_535;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can arise from socket operations.
#[derive(Debug)]
pub enum SocketError {
    /// Underlying I/O error from the OS.
    Io(std::io::Error),
    /// The received datagram could not be decoded as a valid packet.
    Packet(PacketError),
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "socket I/O error: {e}"),
            Self::Packet(e) => write!(f, "packet decode error: {e:?}"),
        }
    }
}

impl std::error::Error for SocketError {}

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

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

/// An async, packet-oriented UDP socket.
///
/// All methods are `&self` so the socket can be shared across tasks if needed.
#[derive(Debug)]
pub struct Socket {
    /// Address this socket is bound to (filled in after OS assigns ephemeral port).
    pub local_addr: SocketAddr,
    inner: UdpSocket,
}

impl Socket {
    /// Bind a new socket to `local_addr`.
    ///
    /// Passing `0.0.0.0:0` lets the OS choose an ephemeral port.
    pub async fn bind(local_addr: SocketAddr) -> Result<Self, SocketError> {
        let inner = UdpSocket::bind(local_addr).await?;
        let local_addr = inner.local_addr()?;
        Ok(Self { local_addr, inner })
    }

    /// Encode `packet` and send it as a single UDP datagram to `dest`.
    pub async fn send_to(&self, packet: &Packet, dest: SocketAddr) -> Result<(), SocketError> {
        let bytes = packet.encode().map_err(SocketError::Packet)?;
        self.inner.send_to(&bytes, dest).await?;
        Ok(())
    }

    /// Receive the next datagram and decode it into a [`Packet`].
    ///
    /// Returns `(packet, sender_address)`.  Datagrams that fail to decode are
    /// returned as `Err` — the caller decides whether to retry.
    pub async fn recv_from(&self) -> Result<(Packet, SocketAddr), SocketError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, addr) = self.inner.recv_from(&mut buf).await?;
        let packet = Packet::decode(&buf[..n])?;
        Ok((packet, addr))
    }
}
