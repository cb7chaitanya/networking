use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    PTR(String),
    MX {
        priority: u16,
        exchange: String,
    },
    TXT(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResourceRecord {
    pub class: u16,
    pub ttl: u32,
    pub data: DnsRecordData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsCacheValue {
    Positive { records: Vec<DnsResourceRecord> },
    Negative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub name: String,
    pub record_type: u16,
    pub expires_at_unix_ms: u64,
    pub value: DnsCacheValue,
}

impl DnsCacheEntry {
    pub fn positive(
        name: impl Into<String>,
        record_type: u16,
        ttl: Duration,
        records: Vec<DnsResourceRecord>,
    ) -> Self {
        Self {
            name: name.into(),
            record_type,
            expires_at_unix_ms: unix_now_ms().saturating_add(ttl.as_millis() as u64),
            value: DnsCacheValue::Positive { records },
        }
    }

    pub fn negative(name: impl Into<String>, record_type: u16, ttl: Duration) -> Self {
        Self {
            name: name.into(),
            record_type,
            expires_at_unix_ms: unix_now_ms().saturating_add(ttl.as_millis() as u64),
            value: DnsCacheValue::Negative,
        }
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_ms
    }

    fn should_replace(&self, existing: &Self) -> bool {
        if self.expires_at_unix_ms != existing.expires_at_unix_ms {
            return self.expires_at_unix_ms > existing.expires_at_unix_ms;
        }

        matches!(
            (&self.value, &existing.value),
            (DnsCacheValue::Positive { .. }, DnsCacheValue::Negative)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpServiceAdvertisement {
    pub service: String,
    pub node_id: u64,
    pub addr: SocketAddr,
    pub generation: u64,
    pub expires_at_unix_ms: u64,
}

impl TcpServiceAdvertisement {
    pub fn new(
        service: impl Into<String>,
        node_id: u64,
        addr: SocketAddr,
        generation: u64,
        ttl: Duration,
    ) -> Self {
        Self {
            service: service.into(),
            node_id,
            addr,
            generation,
            expires_at_unix_ms: unix_now_ms().saturating_add(ttl.as_millis() as u64),
        }
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_ms
    }

    fn should_replace(&self, existing: &Self) -> bool {
        if self.generation != existing.generation {
            return self.generation > existing.generation;
        }
        self.expires_at_unix_ms >= existing.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRecord {
    Dns(DnsCacheEntry),
    Tcp(TcpServiceAdvertisement),
}

#[derive(Debug, Default, Clone)]
pub struct DistributedState {
    dns_entries: HashMap<(String, u16), DnsCacheEntry>,
    tcp_nodes: HashMap<(String, u64), TcpServiceAdvertisement>,
    gossip_cursor: usize,
}

#[derive(Debug, Clone)]
pub struct AppStateHandle {
    inner: Arc<Mutex<DistributedState>>,
}

impl Default for AppStateHandle {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DistributedState::new())),
        }
    }
}

impl AppStateHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish_dns_entry(&self, entry: DnsCacheEntry) {
        self.inner.lock().unwrap().publish_dns_entry(entry);
    }

    pub fn advertise_tcp_service(&self, advertisement: TcpServiceAdvertisement) {
        self.inner
            .lock()
            .unwrap()
            .advertise_tcp_service(advertisement);
    }

    pub fn dns_entry(&self, name: &str, record_type: u16) -> Option<DnsCacheEntry> {
        self.inner.lock().unwrap().dns_entry(name, record_type)
    }

    pub fn tcp_nodes(&self, service: &str) -> Vec<TcpServiceAdvertisement> {
        self.inner.lock().unwrap().tcp_nodes(service)
    }

    pub fn cleanup_expired(&self) {
        self.inner.lock().unwrap().cleanup_expired();
    }

    pub(crate) fn gossip_records(&self, max_payload_bytes: usize) -> Vec<AppRecord> {
        self.inner.lock().unwrap().gossip_records(max_payload_bytes)
    }

    pub(crate) fn merge_records(&self, records: &[AppRecord]) {
        self.inner.lock().unwrap().merge_records(records);
    }
}

impl DistributedState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish_dns_entry(&mut self, entry: DnsCacheEntry) {
        let key = (entry.name.to_lowercase(), entry.record_type);
        match self.dns_entries.get(&key) {
            Some(existing) if !entry.should_replace(existing) => {}
            _ => {
                self.dns_entries.insert(key, entry);
            }
        }
    }

    pub fn advertise_tcp_service(&mut self, advertisement: TcpServiceAdvertisement) {
        let key = (advertisement.service.to_lowercase(), advertisement.node_id);
        match self.tcp_nodes.get(&key) {
            Some(existing) if !advertisement.should_replace(existing) => {}
            _ => {
                self.tcp_nodes.insert(key, advertisement);
            }
        }
    }

    pub fn merge_records(&mut self, records: &[AppRecord]) {
        let now_ms = unix_now_ms();
        for record in records {
            match record {
                AppRecord::Dns(entry) if !entry.is_expired(now_ms) => {
                    self.publish_dns_entry(entry.clone());
                }
                AppRecord::Tcp(entry) if !entry.is_expired(now_ms) => {
                    self.advertise_tcp_service(entry.clone());
                }
                _ => {}
            }
        }
    }

    pub fn dns_entry(&mut self, name: &str, record_type: u16) -> Option<DnsCacheEntry> {
        self.cleanup_expired();
        self.dns_entries
            .get(&(name.to_lowercase(), record_type))
            .cloned()
    }

    pub fn tcp_nodes(&mut self, service: &str) -> Vec<TcpServiceAdvertisement> {
        self.cleanup_expired();
        let mut entries: Vec<_> = self
            .tcp_nodes
            .values()
            .filter(|entry| entry.service.eq_ignore_ascii_case(service))
            .cloned()
            .collect();
        entries.sort_by_key(|entry| entry.node_id);
        entries
    }

    pub fn gossip_records(&mut self, max_payload_bytes: usize) -> Vec<AppRecord> {
        self.cleanup_expired();
        let mut all = self.all_records();
        if all.is_empty() {
            return vec![];
        }

        all.sort_by(compare_records);

        let start = self.gossip_cursor % all.len();
        let mut selected = Vec::new();

        for offset in 0..all.len() {
            let record = all[(start + offset) % all.len()].clone();
            let mut candidate = selected.clone();
            candidate.push(record.clone());

            if encoded_len(&candidate) > max_payload_bytes {
                if selected.is_empty() {
                    break;
                }
                continue;
            }

            selected.push(record);
        }

        self.gossip_cursor = (start + selected.len()) % all.len();
        selected
    }

    pub fn cleanup_expired(&mut self) {
        let now_ms = unix_now_ms();
        self.dns_entries.retain(|_, entry| !entry.is_expired(now_ms));
        self.tcp_nodes.retain(|_, entry| !entry.is_expired(now_ms));
    }

    fn all_records(&self) -> Vec<AppRecord> {
        self.dns_entries
            .values()
            .cloned()
            .map(AppRecord::Dns)
            .chain(self.tcp_nodes.values().cloned().map(AppRecord::Tcp))
            .collect()
    }
}

fn compare_records(left: &AppRecord, right: &AppRecord) -> Ordering {
    match (left, right) {
        (AppRecord::Dns(left), AppRecord::Dns(right)) => (
            left.name.to_lowercase(),
            left.record_type,
        )
            .cmp(&(right.name.to_lowercase(), right.record_type)),
        (AppRecord::Tcp(left), AppRecord::Tcp(right)) => (
            left.service.to_lowercase(),
            left.node_id,
        )
            .cmp(&(right.service.to_lowercase(), right.node_id)),
        (AppRecord::Dns(_), AppRecord::Tcp(_)) => Ordering::Less,
        (AppRecord::Tcp(_), AppRecord::Dns(_)) => Ordering::Greater,
    }
}

#[derive(Debug)]
pub struct AppStateError(String);

impl std::fmt::Display for AppStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for AppStateError {}

impl From<Box<bincode::ErrorKind>> for AppStateError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        Self(error.to_string())
    }
}

pub(crate) fn encode_app_records(records: &[AppRecord]) -> Result<Vec<u8>, AppStateError> {
    Ok(bincode::serialize(records)?)
}

pub(crate) fn decode_app_records(buf: &[u8]) -> Result<Vec<AppRecord>, AppStateError> {
    Ok(bincode::deserialize(buf)?)
}

fn encoded_len(records: &[AppRecord]) -> usize {
    bincode::serialized_size(records).unwrap_or(u64::MAX) as usize
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dns_record() -> DnsCacheEntry {
        DnsCacheEntry::positive(
            "example.com",
            1,
            Duration::from_secs(30),
            vec![DnsResourceRecord {
                class: 1,
                ttl: 30,
                data: DnsRecordData::A(Ipv4Addr::new(1, 1, 1, 1)),
            }],
        )
    }

    #[test]
    fn dns_record_roundtrips() {
        let record = AppRecord::Dns(sample_dns_record());
        let buf = encode_app_records(&[record.clone()]).unwrap();
        let decoded = decode_app_records(&buf).unwrap();
        assert_eq!(decoded, vec![record]);
    }

    #[test]
    fn tcp_service_roundtrips() {
        let record = AppRecord::Tcp(TcpServiceAdvertisement::new(
            "gbn",
            7,
            SocketAddr::from(([127, 0, 0, 1], 9000)),
            2,
            Duration::from_secs(60),
        ));
        let buf = encode_app_records(&[record.clone()]).unwrap();
        let decoded = decode_app_records(&buf).unwrap();
        assert_eq!(decoded, vec![record]);
    }

    #[test]
    fn newer_dns_expiry_wins() {
        let mut state = DistributedState::new();
        let now = unix_now_ms();
        let older = DnsCacheEntry {
            expires_at_unix_ms: now + 10,
            ..sample_dns_record()
        };
        let newer = DnsCacheEntry {
            expires_at_unix_ms: now + 20,
            ..sample_dns_record()
        };

        state.publish_dns_entry(older);
        state.publish_dns_entry(newer.clone());

        assert_eq!(state.dns_entry("example.com", 1), Some(newer));
    }

    #[test]
    fn higher_generation_tcp_entry_wins() {
        let mut state = DistributedState::new();
        let now = unix_now_ms();
        let old = TcpServiceAdvertisement {
            generation: 1,
            expires_at_unix_ms: now + 50,
            ..TcpServiceAdvertisement::new(
                "gbn",
                9,
                SocketAddr::from(([127, 0, 0, 1], 9000)),
                1,
                Duration::from_secs(10),
            )
        };
        let new = TcpServiceAdvertisement {
            generation: 2,
            expires_at_unix_ms: now + 40,
            ..TcpServiceAdvertisement::new(
                "gbn",
                9,
                SocketAddr::from(([127, 0, 0, 1], 9001)),
                2,
                Duration::from_secs(10),
            )
        };

        state.advertise_tcp_service(old);
        state.advertise_tcp_service(new.clone());

        assert_eq!(state.tcp_nodes("gbn"), vec![new]);
    }

    #[test]
    fn gossip_selection_respects_payload_budget() {
        let mut state = DistributedState::new();
        state.publish_dns_entry(sample_dns_record());
        state.advertise_tcp_service(TcpServiceAdvertisement::new(
            "gbn",
            7,
            SocketAddr::from(([127, 0, 0, 1], 9000)),
            1,
            Duration::from_secs(60),
        ));

        let budget = encoded_len(&[AppRecord::Dns(sample_dns_record())]);
        let records = state.gossip_records(budget);
        assert_eq!(records.len(), 1);
    }
}
