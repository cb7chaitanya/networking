use crate::cache::DnsCache;
use crate::dns::{DnsError, DnsPacket, RecordClass, RecordData, RecordType, ResourceRecord};
use crate::network::{extract_ns_and_glue, pick_ns_server, query, ROOT_SERVERS};
use std::collections::HashSet;
use std::sync::{Arc, LockResult, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use rand::Rng;

/// ------------------------------------------------------------
/// Configuration
/// ------------------------------------------------------------
pub const GLOBAL_TIMEOUT: Duration = Duration::from_secs(8);
pub const MAX_CNAME_DEPTH: u8 = 16;

/// ------------------------------------------------------------
/// Metrics
/// ------------------------------------------------------------
#[derive(Default, Debug)]
pub struct ResolverMetrics {
    pub resolve_calls: u64, // total resolve calls
    pub cache_hits: u64,    // served from cache
    pub cache_misses: u64,  // had to query backend
    pub cname_follows: u64, // number of CNAME chains followed
    pub nxdomain_hits: u64, // NXDOMAIN responses
    pub servfail_hits: u64, // SERVFAIL responses
}

/// ------------------------------------------------------------
/// Backend type alias
/// ------------------------------------------------------------
pub type BackendFn =
    dyn Fn(&str, RecordType) -> Result<Vec<ResourceRecord>, DnsError> + Send + Sync;

/// ------------------------------------------------------------
/// DNS Resolver
/// ------------------------------------------------------------
pub struct DnsResolver {
    cache: DnsCache,
    metrics: Mutex<ResolverMetrics>,
    backend: Option<Arc<BackendFn>>,
}

impl DnsResolver {
    /// Default resolver using real network (UDP/TCP) and iterative resolution from root servers.
    pub fn new() -> Self {
        Self {
            cache: DnsCache::new(),
            metrics: Mutex::new(ResolverMetrics::default()),
            backend: None,
        }
    }

    /// Resolver with a mock backend
    pub fn with_backend(backend: Box<BackendFn>) -> Self {
        Self {
            cache: DnsCache::new(),
            metrics: Mutex::new(ResolverMetrics::default()),
            backend: Some(Arc::from(backend)),
        }
    }

    /// Access metrics
    pub fn metrics(&self) -> LockResult<MutexGuard<'_, ResolverMetrics>> {
        self.metrics.lock()
    }

    /// Get cache statistics (hits, misses, evictions)
    pub fn cache_stats(&self) -> (u64, u64, u64) {
        self.cache.stats()
    }

    /// Cleanup expired cache entries
    pub fn cleanup_cache(&self) {
        self.cache.cleanup_expired();
    }

    /// Get nameservers for a domain (with parent fallback)
    pub fn get_nameservers(&self, domain: &str) -> Option<Vec<String>> {
        self.cache.get_ns(domain)
    }

    /// Create a DNS query packet for a domain and record type.
    /// Includes minimal EDNS0 (OPT record) so root servers accept the query.
    pub fn create_query_packet(
        &self,
        id: u16,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Vec<u8>, DnsError> {
        let mut packet = DnsPacket::new_query(id, domain.to_string(), record_type);
        // Minimal EDNS0: OPT pseudo-RR (type 41), UDP payload 4096, so root servers respond
        packet.additionals.push(ResourceRecord {
            name: ".".to_string(),
            record_type: RecordType::Unknown(41), // OPT
            class: RecordClass::Unknown(4096),    // requestor's UDP payload size
            ttl: 0,
            data: RecordData::Unknown(vec![]),
        });
        packet.encode()
    }

    /// Parse a DNS response packet
    /// This can be used for future network implementation
    pub fn parse_response_packet(&self, data: &[u8]) -> Result<DnsPacket, DnsError> {
        let packet = DnsPacket::decode(data)?;

        // Validate it's a response
        if !packet.header.is_response() {
            return Err(DnsError::InvalidPacket("Not a DNS response".into()));
        }

        // Check for errors in header
        match packet.header.rcode() {
            0 => Ok(packet), // No error
            3 => Err(DnsError::NxDomain),
            2 => Err(DnsError::ServFail),
            _ => Err(DnsError::ServFail),
        }
    }

    /// Resolve a domain for a given record type
    pub fn resolve(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        self.resolve_with_timeout(domain, record_type, Instant::now(), 0)
    }

    /// Internal resolve that uses provided start time and depth for tracking.
    /// This ensures recursive calls don't reset the timeout window.
    fn resolve_with_timeout(
        &mut self,
        domain: &str,
        record_type: RecordType,
        start: Instant,
        depth: u8,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        self.metrics().unwrap().resolve_calls += 1;

        // Check cache first (includes negative cache check)
        if let Some(cached) = self.cache.get(domain, record_type) {
            self.metrics.lock().unwrap().cache_hits += 1;
            return Ok(cached);
        }

        // If cache.get returned None, it could be:
        // 1. Cache miss (not in cache)
        // 2. Negative cache hit (domain doesn't exist, cached)
        // The cache handles negative cache internally and returns None for both cases
        // We'll proceed to query backend, which will handle NXDOMAIN if needed
        self.metrics.lock().unwrap().cache_misses += 1;

        // Use backend if provided, otherwise use network (iterative resolution)
        let records = if let Some(backend) = &self.backend {
            let mut visited = HashSet::new();
            self.resolve_with_backend(
                domain.to_string(),
                record_type,
                backend,
                &mut visited,
                start,
                depth,
            )?
        } else {
            self.resolve_via_network(domain, record_type, start, depth)?
        };

        // Cache results - group by (name, type) to use put_multiple efficiently
        use std::collections::HashMap;
        let mut grouped: HashMap<(String, RecordType), Vec<ResourceRecord>> = HashMap::new();
        for r in &records {
            let key = (r.name.clone(), r.record_type);
            grouped.entry(key).or_default().push(r.clone());
        }

        // Cache each group
        for (_, group) in grouped {
            self.cache.put_multiple(group);
        }

        Ok(records)
    }

    /// Internal recursive resolver for mock backend
    fn resolve_with_backend(
        &self,
        domain: String,
        record_type: RecordType,
        backend: &Arc<BackendFn>,
        visited: &mut HashSet<String>,
        start: Instant,
        depth: u8,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        if start.elapsed() > GLOBAL_TIMEOUT {
            self.metrics.lock().unwrap().servfail_hits += 1;
            return Err(DnsError::Timeout);
        }

        if depth >= MAX_CNAME_DEPTH {
            self.metrics.lock().unwrap().servfail_hits += 1;
            return Err(DnsError::ServFail);
        }

        if !visited.insert(domain.clone()) {
            self.metrics.lock().unwrap().servfail_hits += 1;
            return Err(DnsError::ServFail); // prevent infinite loops
        }

        // Query backend
        let response = match backend(&domain, record_type) {
            Ok(records) => records,
            Err(DnsError::NxDomain) if record_type != RecordType::CNAME => {
                self.metrics().unwrap().nxdomain_hits += 1;
                // Cache negative response (NXDOMAIN) with default TTL
                self.cache.put_negative(&domain, record_type, 300);

                // Try CNAME if requested type doesn't exist (per DNS RFC)
                match backend(&domain, RecordType::CNAME) {
                    Ok(cname_records) => cname_records,
                    Err(DnsError::NxDomain) => {
                        // Also cache negative for CNAME
                        self.cache.put_negative(&domain, RecordType::CNAME, 300);
                        return Err(DnsError::NxDomain);
                    }
                    Err(e) => {
                        self.metrics.lock().unwrap().servfail_hits += 1;
                        return Err(e);
                    }
                }
            }
            Err(DnsError::NxDomain) => {
                // Direct NXDOMAIN for CNAME query
                self.metrics().unwrap().nxdomain_hits += 1;
                self.cache.put_negative(&domain, record_type, 300);
                return Err(DnsError::NxDomain);
            }
            Err(DnsError::ServFail) => {
                self.metrics.lock().unwrap().servfail_hits += 1;
                // Don't cache SERVFAIL (transient error)
                return Err(DnsError::ServFail);
            }
            Err(e) => {
                self.metrics.lock().unwrap().servfail_hits += 1;
                return Err(e);
            }
        };

        // Handle CNAME chaining
        if let Some(cname_rr) = response.iter().find(|r| r.record_type == RecordType::CNAME) {
            if let RecordData::CNAME(target) = &cname_rr.data {
                self.metrics().unwrap().cname_follows += 1;
                let mut chained = self.resolve_with_backend(
                    target.clone(),
                    record_type,
                    backend,
                    visited,
                    start,
                    depth + 1,
                )?;
                chained.insert(0, cname_rr.clone()); // include the CNAME itself
                return Ok(chained);
            }
        }

        Ok(response)
    }

    /// Iterative resolution over the network starting from root servers.
    fn resolve_via_network(
        &mut self,
        domain: &str,
        record_type: RecordType,
        start: Instant,
        depth: u8,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        if start.elapsed() > GLOBAL_TIMEOUT {
            self.metrics.lock().unwrap().servfail_hits += 1;
            return Err(DnsError::Timeout);
        }

        if depth >= MAX_CNAME_DEPTH {
            self.metrics.lock().unwrap().servfail_hits += 1;
            return Err(DnsError::ServFail);
        }

        let query_id: u16 = rand::rng().random();
        let request = self.create_query_packet(query_id, domain, record_type)?;
        let mut servers: Vec<String> = ROOT_SERVERS.iter().map(|s| (*s).to_string()).collect();
        let mut visited_ns = HashSet::<String>::new();

        'outer: loop {
            if start.elapsed() > GLOBAL_TIMEOUT {
                self.metrics.lock().unwrap().servfail_hits += 1;
                return Err(DnsError::Timeout);
            }

            let mut last_error = None;
            for server in &servers {
                let response_bytes = match query(server, &request) {
                    Ok(b) => b,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                };

                let packet = match self.parse_response_packet(&response_bytes) {
                    Ok(p) => p,
                    Err(DnsError::NxDomain) => {
                        self.metrics.lock().unwrap().nxdomain_hits += 1;
                        self.cache.put_negative(domain, record_type, 300);
                        return Err(DnsError::NxDomain);
                    }
                    Err(DnsError::ServFail) => {
                        self.metrics.lock().unwrap().servfail_hits += 1;
                        last_error = Some(DnsError::ServFail);
                        continue;
                    }
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                };

                // Cache referral data (NS and glue A) for future lookups
                for rr in packet.authorities.iter().chain(packet.additionals.iter()) {
                    self.cache.put(rr.clone());
                }

                // We have a response with rcode 0
                if !packet.answers.is_empty() {
                    let cname_rr = packet
                        .answers
                        .iter()
                        .find(|r| r.record_type == RecordType::CNAME);
                    let has_requested = packet.answers.iter().any(|r| r.record_type == record_type);

                    if has_requested {
                        let answers: Vec<ResourceRecord> = packet
                            .answers
                            .into_iter()
                            .filter(|r| r.record_type == record_type)
                            .collect();
                        return Ok(answers);
                    }
                    if let Some(cname_rr) = cname_rr {
                        if let RecordData::CNAME(target) = &cname_rr.data {
                            self.metrics.lock().unwrap().cname_follows += 1;
                            let mut chained =
                                self.resolve_via_network(target, record_type, start, depth + 1)?;
                            chained.insert(0, cname_rr.clone());
                            return Ok(chained);
                        }
                    }
                }

                // Referral: use authority NS and additional glue
                let ns_and_glue = extract_ns_and_glue(&packet);
                if ns_and_glue.is_empty() {
                    self.metrics.lock().unwrap().servfail_hits += 1;
                    return Err(DnsError::ServFail);
                }

                if let Some(server_ip) = pick_ns_server(&ns_and_glue) {
                    servers = vec![server_ip];
                    continue 'outer;
                }

                // No glue: resolve first NS name to get an IP
                for (ns_name, _) in &ns_and_glue {
                    if visited_ns.insert(ns_name.clone()) {
                        if let Ok(a_records) =
                            self.resolve_with_timeout(ns_name, RecordType::A, start, depth + 1)
                        {
                            if let Some(rr) = a_records
                                .into_iter()
                                .find(|r| r.record_type == RecordType::A)
                            {
                                if let RecordData::A(addr) = rr.data {
                                    servers = vec![addr.to_string()];
                                    continue 'outer;
                                }
                            }
                        }
                    }
                }
                self.metrics.lock().unwrap().servfail_hits += 1;
                return Err(last_error.unwrap_or(DnsError::ServFail));
            }

            if let Some(e) = last_error {
                self.metrics.lock().unwrap().servfail_hits += 1;
                return Err(e);
            }
            self.metrics.lock().unwrap().servfail_hits += 1;
            return Err(DnsError::ServFail);
        }
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}
