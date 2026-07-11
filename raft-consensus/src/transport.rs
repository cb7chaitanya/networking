//! Async TCP transport for Raft RPC messages.
//!
//! ## Frame format (length-prefixed)
//!
//! ```text
//! [4: body_len as u32 BE] [8: from as u64 BE] [8: to as u64 BE] [N: wire-encoded Rpc]
//! ```
//!
//! Each peer gets a dedicated writer task that maintains the outgoing TCP
//! connection and automatically reconnects with exponential back-off on failure.
//! Messages buffered during a disconnect are flushed before resuming normal
//! operation.
//!
//! ## Running a node
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use raft_consensus::node::ClusterConfig;
//! use raft_consensus::transport::NodeRunner;
//!
//! # async fn example() -> std::io::Result<()> {
//! let config = ClusterConfig {
//!     election_timeout_min: 15,
//!     election_timeout_max: 30,
//!     heartbeat_interval: 5,
//!     pre_vote: false,
//! };
//!
//! let (runner, handle) = NodeRunner::new(
//!     1,                                                   // node ID
//!     vec![(2, "127.0.0.1:7002".parse().unwrap()),
//!          (3, "127.0.0.1:7003".parse().unwrap())],       // peers
//!     "127.0.0.1:7001".parse().unwrap(),                  // listen addr
//!     config,
//!     10,                                                  // tick_ms
//! ).await?;
//!
//! tokio::spawn(runner.run());
//! // handle.propose(b"hello".to_vec());
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time;

use crate::message::Envelope;
use crate::metrics::RaftMetrics;
use crate::node::{ClusterConfig, RaftNode};
use crate::state::NodeId;
use crate::wire;

// ── Constants ────────────────────────────────────────────────────────────────

const RECONNECT_BASE_MS: u64 = 100;
const RECONNECT_MAX_MS: u64 = 5_000;

/// 16-byte fixed prefix inside each frame body: 8 bytes `from` + 8 bytes `to`.
const ENVELOPE_HEADER: usize = 16;

// ── Frame codec ──────────────────────────────────────────────────────────────

/// Encode an [`Envelope`] as a length-prefixed frame.
///
/// Layout:
/// ```text
/// [4: body_len u32 BE] [8: from u64 BE] [8: to u64 BE] [N: wire-encoded Rpc]
/// ```
pub fn encode_frame(envelope: &Envelope) -> Vec<u8> {
    let rpc_bytes = wire::encode(&envelope.payload);
    let body_len = ENVELOPE_HEADER + rpc_bytes.len();
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    frame.extend_from_slice(&envelope.from.to_be_bytes());
    frame.extend_from_slice(&envelope.to.to_be_bytes());
    frame.extend_from_slice(&rpc_bytes);
    frame
}

/// Read one frame from `stream` and decode it into an `(Envelope, bytes_read)` pair.
async fn read_frame(stream: &mut TcpStream) -> tokio::io::Result<(Envelope, u64)> {
    let body_len = stream.read_u32().await? as usize;
    if body_len < ENVELOPE_HEADER {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "frame body too short",
        ));
    }
    let from = stream.read_u64().await?;
    let to = stream.read_u64().await?;

    let rpc_len = body_len - ENVELOPE_HEADER;
    let mut rpc_bytes = vec![0u8; rpc_len];
    stream.read_exact(&mut rpc_bytes).await?;

    let payload = wire::decode(&rpc_bytes).map_err(|e| {
        tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e.to_string())
    })?;

    // 4-byte length prefix + body.
    let bytes_read = (4 + body_len) as u64;
    Ok((Envelope { from, to, payload }, bytes_read))
}

// ── TcpTransport ─────────────────────────────────────────────────────────────

/// Manages outgoing peer connections and the incoming connection listener.
///
/// Created via [`TcpTransport::new`], which also returns an
/// [`IncomingRx`] channel for the event loop to receive decoded envelopes.
pub type IncomingRx = mpsc::UnboundedReceiver<Envelope>;

pub struct TcpTransport {
    #[allow(dead_code)]
    node_id: NodeId,
    /// Senders to each outgoing peer writer task (keyed by peer NodeId).
    peer_txs: HashMap<NodeId, mpsc::UnboundedSender<Vec<u8>>>,
    /// Clone this to hand to newly accepted reader tasks.
    incoming_tx: mpsc::UnboundedSender<Envelope>,
    /// Optional metrics store — shared with writer/reader tasks.
    metrics: Option<Arc<RaftMetrics>>,
}

impl TcpTransport {
    /// Create a transport and its paired incoming-message receiver.
    pub fn new(node_id: NodeId) -> (Self, IncomingRx) {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        (
            Self {
                node_id,
                peer_txs: HashMap::new(),
                incoming_tx,
                metrics: None,
            },
            incoming_rx,
        )
    }

    /// Attach a metrics store. Must be called before `add_peer` / `listen`
    /// for the store to be visible to background tasks.
    pub fn set_metrics(&mut self, m: Arc<RaftMetrics>) {
        self.metrics = Some(m);
    }

    /// Register a peer and spawn a background writer task that maintains the
    /// outgoing TCP connection with automatic reconnect.
    pub fn add_peer(&mut self, peer_id: NodeId, addr: SocketAddr) {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(peer_writer_task(peer_id, addr, rx, self.metrics.clone()));
        self.peer_txs.insert(peer_id, tx);
    }

    /// Bind `addr` and start accepting incoming connections. Each connection
    /// gets its own reader task that pushes decoded envelopes into the shared
    /// incoming channel. Returns the actual bound address (useful when port 0
    /// is passed).
    pub async fn listen(&self, addr: SocketAddr) -> tokio::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        let incoming_tx = self.incoming_tx.clone();
        tokio::spawn(accept_loop(listener, incoming_tx, self.metrics.clone()));
        Ok(bound)
    }

    /// Send an envelope to `envelope.to`. Drops silently if the peer is
    /// unknown; the writer task handles connection failures internally.
    pub fn send(&self, envelope: &Envelope) {
        if let Some(tx) = self.peer_txs.get(&envelope.to) {
            let frame = encode_frame(envelope);
            let _ = tx.send(frame);
        }
    }
}

// ── Background tasks ─────────────────────────────────────────────────────────

/// Accept incoming TCP connections and spawn a reader task per connection.
async fn accept_loop(
    listener: TcpListener,
    incoming_tx: mpsc::UnboundedSender<Envelope>,
    metrics: Option<Arc<RaftMetrics>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer_addr)) => {
                let tx = incoming_tx.clone();
                tokio::spawn(reader_task(stream, tx, metrics.clone()));
            }
            Err(_) => break, // listener was closed
        }
    }
}

/// Read frames from an accepted connection and forward them as envelopes.
async fn reader_task(
    mut stream: TcpStream,
    tx: mpsc::UnboundedSender<Envelope>,
    metrics: Option<Arc<RaftMetrics>>,
) {
    loop {
        match read_frame(&mut stream).await {
            Ok((envelope, bytes)) => {
                if let Some(ref m) = metrics {
                    m.add_transport_bytes_received(bytes);
                }
                if tx.send(envelope).is_err() {
                    break; // receiver dropped
                }
            }
            Err(_) => break, // connection closed or corrupt frame
        }
    }
}

/// Maintain an outgoing connection to `addr` with exponential back-off reconnect.
///
/// Messages received on `rx` while disconnected are buffered and flushed
/// once the connection is re-established. Back-off resets to the base value
/// on each successful connect.
async fn peer_writer_task(
    _peer_id: NodeId,
    addr: SocketAddr,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    metrics: Option<Arc<RaftMetrics>>,
) {
    let mut pending: std::collections::VecDeque<Vec<u8>> = Default::default();
    let mut backoff = Duration::from_millis(RECONNECT_BASE_MS);

    loop {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                backoff = Duration::from_millis(RECONNECT_BASE_MS);

                // Flush messages that arrived while we were disconnected.
                let mut flush_ok = true;
                while let Some(frame) = pending.pop_front() {
                    let n = frame.len() as u64;
                    if stream.write_all(&frame).await.is_err() {
                        pending.push_front(frame);
                        flush_ok = false;
                        break;
                    }
                    if let Some(ref m) = metrics {
                        m.add_transport_bytes_sent(n);
                    }
                }
                if !flush_ok {
                    // Still can't write — reconnect immediately.
                    continue;
                }

                // Normal operation: drain channel into the connection.
                loop {
                    match rx.recv().await {
                        Some(frame) => {
                            let n = frame.len() as u64;
                            if stream.write_all(&frame).await.is_err() {
                                pending.push_back(frame);
                                break; // reconnect
                            }
                            if let Some(ref m) = metrics {
                                m.add_transport_bytes_sent(n);
                            }
                        }
                        None => return, // sender dropped; node shut down
                    }
                }
            }
            Err(_) => {
                if let Some(ref m) = metrics {
                    m.inc_transport_reconnects();
                }
                time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(RECONNECT_MAX_MS));
            }
        }
    }
}

// ── NodeRunner ────────────────────────────────────────────────────────────────

/// Drives a [`RaftNode`] over TCP. Owns the node and all I/O channels.
///
/// Create via [`NodeRunner::new`], then call [`NodeRunner::run`] as a
/// `tokio::spawn`-ed task or directly with `.await`.
pub struct NodeRunner {
    node: RaftNode,
    transport: TcpTransport,
    incoming_rx: IncomingRx,
    propose_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tick_ms: u64,
}

/// Returned from [`NodeRunner::new`]; lets callers propose entries and inspect
/// node state without holding a reference to the event loop.
pub struct NodeHandle {
    /// Send raw bytes here to propose a Raft log entry.
    pub propose_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Shared metrics store updated by the node.
    pub metrics: Arc<RaftMetrics>,
    /// The bound listen address (may differ from the requested addr if port 0
    /// was used).
    pub bound_addr: SocketAddr,
}

impl NodeHandle {
    /// Enqueue a proposal. The running node will accept it if it is leader.
    pub fn propose(&self, data: Vec<u8>) {
        let _ = self.propose_tx.send(data);
    }
}

impl NodeRunner {
    /// Build a node runner and its control handle.
    ///
    /// * `id` — unique node ID (must be > 0).
    /// * `peers` — `(NodeId, SocketAddr)` pairs for every other cluster member.
    /// * `bind_addr` — address this node listens on; use port 0 for an
    ///   OS-assigned ephemeral port.
    /// * `config` — Raft timing configuration (all values in ticks).
    /// * `tick_ms` — real-time milliseconds per logical tick.
    pub async fn new(
        id: NodeId,
        peers: Vec<(NodeId, SocketAddr)>,
        bind_addr: SocketAddr,
        config: ClusterConfig,
        tick_ms: u64,
    ) -> tokio::io::Result<(Self, NodeHandle)> {
        let metrics = Arc::new(RaftMetrics::new());

        let peer_ids: Vec<NodeId> = peers.iter().map(|(id, _)| *id).collect();
        let node = RaftNode::new(id, peer_ids, config)
            .with_metrics(Arc::clone(&metrics));

        let (mut transport, incoming_rx) = TcpTransport::new(id);
        transport.set_metrics(Arc::clone(&metrics));
        for (peer_id, peer_addr) in &peers {
            transport.add_peer(*peer_id, *peer_addr);
        }
        let bound_addr = transport.listen(bind_addr).await?;

        let (propose_tx, propose_rx) = mpsc::unbounded_channel();

        let runner = NodeRunner {
            node,
            transport,
            incoming_rx,
            propose_rx,
            tick_ms,
        };
        let handle = NodeHandle {
            propose_tx,
            metrics,
            bound_addr,
        };
        Ok((runner, handle))
    }

    /// Run the Raft event loop until the process exits.
    ///
    /// Drives the node at `tick_ms` intervals, delivers incoming network
    /// messages, accepts proposals, and flushes the outbox after every state
    /// transition.
    pub async fn run(mut self) {
        let mut ticker = time::interval(Duration::from_millis(self.tick_ms));
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.node.tick(1);
                }
                Some(envelope) = self.incoming_rx.recv() => {
                    self.node.step(envelope);
                }
                Some(data) = self.propose_rx.recv() => {
                    self.node.propose(data);
                }
            }

            // After every state transition, flush the outbox and applied log.
            for msg in self.node.drain_messages() {
                self.transport.send(&msg);
            }
            // Drain applied entries (in a real system you'd hand them to the
            // state machine; here we discard them).
            let _ = self.node.drain_applied();
        }
    }

    /// Like `run`, but accepts an additional `Arc<Mutex<NodeState>>` so the
    /// demo can read live node state from outside the event loop.
    pub async fn run_with_state(mut self, state: Arc<Mutex<LiveNodeState>>) {
        let mut ticker = time::interval(Duration::from_millis(self.tick_ms));
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.node.tick(1);
                }
                Some(envelope) = self.incoming_rx.recv() => {
                    self.node.step(envelope);
                }
                Some(data) = self.propose_rx.recv() => {
                    self.node.propose(data);
                }
            }

            for msg in self.node.drain_messages() {
                self.transport.send(&msg);
            }
            let _ = self.node.drain_applied();

            // Publish a snapshot of observable state.
            if let Ok(mut s) = state.lock() {
                s.is_leader = self.node.is_leader();
                s.commit_index = self.node.commit_index();
            }
        }
    }
}

/// Observable state published by a running node (for demo use).
#[derive(Default)]
pub struct LiveNodeState {
    pub is_leader: bool,
    pub commit_index: u64,
}
