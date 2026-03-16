use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gossip_membership::app_state::{AppStateHandle, TcpServiceAdvertisement};

#[derive(Clone)]
pub struct GossipDiscovery {
    app_state: AppStateHandle,
    service: String,
    ttl: Duration,
    generation: Arc<AtomicU64>,
}

impl GossipDiscovery {
    pub fn new(app_state: AppStateHandle, service: impl Into<String>) -> Self {
        Self {
            app_state,
            service: service.into(),
            ttl: Duration::from_secs(30),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn advertise(&self, node_id: u64, addr: SocketAddr) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.app_state
            .advertise_tcp_service(TcpServiceAdvertisement::new(
                self.service.clone(),
                node_id,
                addr,
                generation,
                self.ttl,
            ));
        generation
    }

    pub fn peers(&self) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self
            .app_state
            .tcp_nodes(&self.service)
            .into_iter()
            .map(|entry| entry.addr)
            .collect();
        peers.sort();
        peers.dedup();
        peers
    }

    pub fn pick_peer(&self) -> Option<SocketAddr> {
        self.peers().into_iter().next()
    }
}
