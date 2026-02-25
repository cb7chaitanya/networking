use crate::dns::{ResourceRecord, RecordType, RecordData};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// Cached DNS entry (positive or negative)
#[derive(Clone)]
enum CacheEntry {
    Positive {
        records: Vec<ResourceRecord>,
        expires_at: Instant,
    },
    Negative {
        expires_at: Instant,
    },
}

/// Thread-safe DNS cache with LRU eviction
#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<RwLock<CacheInner>>,
}

struct CacheInner {
    map: HashMap<(String, RecordType), CacheEntry>,
    lru: VecDeque<(String, RecordType)>,
    capacity: usize,

    // Metrics
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                map: HashMap::new(),
                lru: VecDeque::new(),
                capacity,
                hits: 0,
                misses: 0,
                evictions: 0,
            })),
        }
    }

    /// Lookup cached RRset
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<Vec<ResourceRecord>> {
        let key = (name.to_lowercase(), record_type);
        let mut inner = self.inner.write().unwrap();

        // Clone what we need first to avoid borrow conflicts
        let result = match inner.map.get(&key) {
            Some(CacheEntry::Positive { records, expires_at }) if *expires_at > Instant::now() => {
                Some(records.clone())
            }
            Some(CacheEntry::Negative { expires_at }) if *expires_at > Instant::now() => {
                Some(Vec::new()) // Negative cache hit
            }
            _ => None,
        };

        // Now perform mutable operations after the immutable borrow is released
        match result {
            Some(records) if !records.is_empty() => {
                inner.hits += 1;
                inner.touch(&key);
                Some(records)
            }
            Some(_) => {
                // Negative cache hit
                inner.hits += 1;
                None
            }
            None => {
                inner.misses += 1;
                inner.map.remove(&key);
                inner.lru.retain(|k| k != &key);
                None
            }
        }
    }

    /// Cache single RR
    pub fn put(&self, record: ResourceRecord) {
        self.put_multiple(vec![record]);
    }

    /// Cache homogeneous RRset
    pub fn put_multiple(&self, records: Vec<ResourceRecord>) {
        if records.is_empty() {
            return;
        }

        let name = records[0].name.to_lowercase();
        let rtype = records[0].record_type;

        for r in &records {
            if r.name.to_lowercase() != name || r.record_type != rtype {
                panic!("put_multiple requires homogeneous RRsets");
            }
        }

        let valid: Vec<_> = records.into_iter().filter(|r| r.ttl > 0).collect();
        if valid.is_empty() {
            return;
        }

        let min_ttl = valid.iter().map(|r| r.ttl).min().unwrap();
        let expires_at = Instant::now() + Duration::from_secs(min_ttl as u64);

        let mut inner = self.inner.write().unwrap();
        inner.insert(
            (name, rtype),
            CacheEntry::Positive {
                records: valid,
                expires_at,
            },
        );
    }

    /// Cache negative response (NXDOMAIN / NODATA)
    pub fn put_negative(&self, name: &str, record_type: RecordType, ttl: u32) {
        if ttl == 0 {
            return;
        }

        let expires_at = Instant::now() + Duration::from_secs(ttl as u64);
        let key = (name.to_lowercase(), record_type);

        let mut inner = self.inner.write().unwrap();
        inner.insert(key, CacheEntry::Negative { expires_at });
    }

    /// NS lookup with parent fallback
    pub fn get_ns(&self, domain: &str) -> Option<Vec<String>> {
        let parts: Vec<&str> = domain.split('.').collect();

        for i in 0..parts.len() {
            let sub = parts[i..].join(".");
            if let Some(records) = self.get(&sub, RecordType::NS) {
                let ns: Vec<String> = records.iter().filter_map(|r| {
                    if let RecordData::NS(n) = &r.data {
                        Some(n.clone())
                    } else {
                        None
                    }
                }).collect();

                if !ns.is_empty() {
                    return Some(ns);
                }
            }
        }
        None
    }

    /// Remove expired entries
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut inner = self.inner.write().unwrap();

        inner.map.retain(|_, entry| match entry {
            CacheEntry::Positive { expires_at, .. } => *expires_at > now,
            CacheEntry::Negative { expires_at } => *expires_at > now,
        });
    }

    /// Cache metrics
    pub fn stats(&self) -> (u64, u64, u64) {
        let inner = self.inner.read().unwrap();
        (inner.hits, inner.misses, inner.evictions)
    }
}

impl CacheInner {
    fn insert(&mut self, key: (String, RecordType), entry: CacheEntry) {
        if !self.map.contains_key(&key) && self.map.len() >= self.capacity {
            if let Some(oldest) = self.lru.pop_front() {
                self.map.remove(&oldest);
                self.evictions += 1;
            }
        }

        self.lru.retain(|k| k != &key);
        self.lru.push_back(key.clone());
        self.map.insert(key, entry);
    }

    fn touch(&mut self, key: &(String, RecordType)) {
        self.lru.retain(|k| k != key);
        self.lru.push_back(key.clone());
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{RecordClass};
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    fn a(name: &str, ip: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.into(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl,
            data: RecordData::A(ip.parse::<Ipv4Addr>().unwrap()),
        }
    }

    fn ns(name: &str, host: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.into(),
            record_type: RecordType::NS,
            class: RecordClass::IN,
            ttl,
            data: RecordData::NS(host.into()),
        }
    }

    #[test]
    fn positive_cache_hit() {
        let cache = DnsCache::new();
        cache.put(a("example.com", "1.1.1.1", 300));
        assert!(cache.get("example.com", RecordType::A).is_some());
    }

    #[test]
    fn ttl_expiry() {
        let cache = DnsCache::new();
        cache.put(a("example.com", "1.1.1.1", 1));
        sleep(Duration::from_secs(2));
        assert!(cache.get("example.com", RecordType::A).is_none());
    }

    #[test]
    fn negative_cache() {
        let cache = DnsCache::new();
        cache.put_negative("nope.com", RecordType::A, 2);
        assert!(cache.get("nope.com", RecordType::A).is_none());
        sleep(Duration::from_secs(3));
        assert!(cache.get("nope.com", RecordType::A).is_none());
    }

    #[test]
    fn lru_eviction() {
        let cache = DnsCache::with_capacity(2);
        cache.put(a("a.com", "1.1.1.1", 300));
        cache.put(a("b.com", "2.2.2.2", 300));
        cache.put(a("c.com", "3.3.3.3", 300));

        assert!(cache.get("a.com", RecordType::A).is_none());
        assert!(cache.get("b.com", RecordType::A).is_some());
        assert!(cache.get("c.com", RecordType::A).is_some());
    }

    #[test]
    fn ns_parent_fallback() {
        let cache = DnsCache::new();
        cache.put(ns("example.com", "ns1.example.com", 300));

        let ns = cache.get_ns("sub.example.com").unwrap();
        assert_eq!(ns, vec!["ns1.example.com"]);
    }

    #[test]
    fn stats_work() {
        let cache = DnsCache::new();
        cache.put(a("example.com", "1.1.1.1", 300));

        cache.get("example.com", RecordType::A);
        cache.get("missing.com", RecordType::A);

        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn put_multiple_records() {
        let cache = DnsCache::new();
        let records = vec![
            a("multi.com", "1.1.1.1", 300),
            a("multi.com", "1.1.1.2", 300),
            a("multi.com", "1.1.1.3", 300),
        ];
        cache.put_multiple(records);

        let cached = cache.get("multi.com", RecordType::A).unwrap();
        assert_eq!(cached.len(), 3);
    }

    #[test]
    #[should_panic(expected = "put_multiple requires homogeneous RRsets")]
    fn put_multiple_heterogeneous_panics() {
        let cache = DnsCache::new();
        let records = vec![
            a("test.com", "1.1.1.1", 300),
            ns("test.com", "ns.test.com", 300), // Different type
        ];
        cache.put_multiple(records);
    }

    #[test]
    #[should_panic(expected = "put_multiple requires homogeneous RRsets")]
    fn put_multiple_different_names_panics() {
        let cache = DnsCache::new();
        let records = vec![
            a("test1.com", "1.1.1.1", 300),
            a("test2.com", "1.1.1.2", 300), // Different name
        ];
        cache.put_multiple(records);
    }

    #[test]
    fn put_multiple_ttl_zero_filtered() {
        let cache = DnsCache::new();
        let records = vec![
            a("zero.com", "1.1.1.1", 0), // TTL=0 should be filtered
            a("zero.com", "1.1.1.2", 300),
        ];
        cache.put_multiple(records);

        let cached = cache.get("zero.com", RecordType::A).unwrap();
        assert_eq!(cached.len(), 1);
        match &cached[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "1.1.1.2"),
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn put_multiple_all_ttl_zero_not_cached() {
        let cache = DnsCache::new();
        let records = vec![
            a("allzero.com", "1.1.1.1", 0),
            a("allzero.com", "1.1.1.2", 0),
        ];
        cache.put_multiple(records);

        assert!(cache.get("allzero.com", RecordType::A).is_none());
    }

    #[test]
    fn put_multiple_empty_vec_noop() {
        let cache = DnsCache::new();
        cache.put_multiple(vec![]);
        // Should not panic or crash
        assert!(cache.get("any.com", RecordType::A).is_none());
    }

    #[test]
    fn put_multiple_min_ttl_used() {
        let cache = DnsCache::new();
        let records = vec![
            a("minttl.com", "1.1.1.1", 300),
            a("minttl.com", "1.1.1.2", 60), // Min TTL
            a("minttl.com", "1.1.1.3", 120),
        ];
        cache.put_multiple(records);

        // Record should expire after 60 seconds (min TTL)
        let cached = cache.get("minttl.com", RecordType::A);
        assert!(cached.is_some());

        sleep(Duration::from_secs(61));
        assert!(cache.get("minttl.com", RecordType::A).is_none());
    }

    #[test]
    fn case_insensitive_lookup() {
        let cache = DnsCache::new();
        cache.put(a("Example.COM", "1.1.1.1", 300));

        // Should find regardless of case
        assert!(cache.get("example.com", RecordType::A).is_some());
        assert!(cache.get("EXAMPLE.COM", RecordType::A).is_some());
        assert!(cache.get("ExAmPlE.CoM", RecordType::A).is_some());
    }

    #[test]
    fn case_insensitive_storage() {
        let cache = DnsCache::new();
        cache.put(a("test.com", "1.1.1.1", 300));
        cache.put(a("TEST.COM", "1.1.1.2", 300)); // Should overwrite

        let cached = cache.get("test.com", RecordType::A).unwrap();
        assert_eq!(cached.len(), 1);
        match &cached[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "1.1.1.2"),
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn different_record_types_separate() {
        let cache = DnsCache::new();
        cache.put(a("test.com", "1.1.1.1", 300));
        cache.put(ns("test.com", "ns.test.com", 300));

        let a_records = cache.get("test.com", RecordType::A).unwrap();
        let ns_records = cache.get("test.com", RecordType::NS).unwrap();

        assert_eq!(a_records.len(), 1);
        assert_eq!(ns_records.len(), 1);
        match &a_records[0].data {
            RecordData::A(_) => {},
            _ => panic!("Expected A record"),
        }
        match &ns_records[0].data {
            RecordData::NS(_) => {},
            _ => panic!("Expected NS record"),
        }
    }

    #[test]
    fn multiple_ns_records() {
        let cache = DnsCache::new();
        let ns_records = vec![
            ns("example.com", "ns1.example.com", 300),
            ns("example.com", "ns2.example.com", 300),
            ns("example.com", "ns3.example.com", 300),
        ];
        cache.put_multiple(ns_records);

        let cached = cache.get("example.com", RecordType::NS).unwrap();
        assert_eq!(cached.len(), 3);

        let ns_list = cache.get_ns("example.com").unwrap();
        assert_eq!(ns_list.len(), 3);
        assert!(ns_list.contains(&"ns1.example.com".to_string()));
        assert!(ns_list.contains(&"ns2.example.com".to_string()));
        assert!(ns_list.contains(&"ns3.example.com".to_string()));
    }

    #[test]
    fn get_ns_multiple_levels() {
        let cache = DnsCache::new();
        cache.put(ns("com", "ns.com", 300));
        cache.put(ns("example.com", "ns1.example.com", 300));

        // Should find example.com NS first
        let ns_list = cache.get_ns("sub.example.com").unwrap();
        assert_eq!(ns_list, vec!["ns1.example.com"]);

        // Should fall back to com NS
        let ns_list = cache.get_ns("other.com").unwrap();
        assert_eq!(ns_list, vec!["ns.com"]);
    }

    #[test]
    fn get_ns_root_domain() {
        let cache = DnsCache::new();
        cache.put(ns("example.com", "ns.example.com", 300));

        let ns_list = cache.get_ns("example.com").unwrap();
        assert_eq!(ns_list, vec!["ns.example.com"]);
    }

    #[test]
    fn get_ns_not_found() {
        let cache = DnsCache::new();
        assert!(cache.get_ns("nonexistent.com").is_none());
    }

    #[test]
    fn negative_cache_ttl_zero_not_cached() {
        let cache = DnsCache::new();
        cache.put_negative("nottl.com", RecordType::A, 0);
        // Should not be cached
        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 0);
    }

    #[test]
    fn negative_cache_expires() {
        let cache = DnsCache::new();
        cache.put_negative("expire.com", RecordType::A, 1);
        
        // Should be cached (returns None but counts as hit)
        cache.get("expire.com", RecordType::A);
        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);

        sleep(Duration::from_secs(2));
        cache.cleanup_expired();

        // After expiry, should be a miss
        cache.get("expire.com", RecordType::A);
        let (hits, misses, _) = cache.stats();
        assert_eq!(misses, 1);
        assert_eq!(hits, 1); // Still 1 from the first get
    }

    #[test]
    fn cleanup_expired_removes_positive() {
        let cache = DnsCache::new();
        cache.put(a("expire1.com", "1.1.1.1", 1));
        cache.put(a("expire2.com", "2.2.2.2", 1));
        cache.put(a("keep.com", "3.3.3.3", 300));

        sleep(Duration::from_secs(2));
        cache.cleanup_expired();

        assert!(cache.get("expire1.com", RecordType::A).is_none());
        assert!(cache.get("expire2.com", RecordType::A).is_none());
        assert!(cache.get("keep.com", RecordType::A).is_some());
    }

    #[test]
    fn cleanup_expired_removes_negative() {
        let cache = DnsCache::new();
        cache.put_negative("neg1.com", RecordType::A, 1);
        cache.put_negative("neg2.com", RecordType::A, 1);
        cache.put_negative("keep.com", RecordType::A, 300);

        sleep(Duration::from_secs(2));
        cache.cleanup_expired();

        // After cleanup, expired negative entries should be gone
        cache.get("neg1.com", RecordType::A);
        cache.get("neg2.com", RecordType::A);
        let (hits, misses, _) = cache.stats();
        // Should be misses now (not cached)
        assert!(misses >= 2);
        assert_eq!(hits, 0);
    }

    #[test]
    fn stats_hits_tracking() {
        let cache = DnsCache::new();
        cache.put(a("stats.com", "1.1.1.1", 300));

        // Multiple hits
        cache.get("stats.com", RecordType::A);
        cache.get("stats.com", RecordType::A);
        cache.get("stats.com", RecordType::A);

        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 3);
        assert_eq!(misses, 0);
    }

    #[test]
    fn stats_misses_tracking() {
        let cache = DnsCache::new();
        
        cache.get("missing1.com", RecordType::A);
        cache.get("missing2.com", RecordType::A);
        cache.get("missing3.com", RecordType::A);

        let (hits, misses, _) = cache.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 3);
    }

    #[test]
    fn stats_evictions_tracking() {
        let cache = DnsCache::with_capacity(3);
        
        cache.put(a("a.com", "1.1.1.1", 300));
        cache.put(a("b.com", "2.2.2.2", 300));
        cache.put(a("c.com", "3.3.3.3", 300));
        cache.put(a("d.com", "4.4.4.4", 300)); // Should evict a.com

        let (_, _, evictions) = cache.stats();
        assert!(evictions >= 1);
    }

    #[test]
    fn lru_touch_updates_order() {
        let cache = DnsCache::with_capacity(2);
        
        cache.put(a("a.com", "1.1.1.1", 300));
        cache.put(a("b.com", "2.2.2.2", 300));
        
        // Touch a.com (should move it to end of LRU)
        cache.get("a.com", RecordType::A);
        
        // Add c.com - should evict b.com (oldest untouched), not a.com
        cache.put(a("c.com", "3.3.3.3", 300));

        assert!(cache.get("a.com", RecordType::A).is_some());
        assert!(cache.get("b.com", RecordType::A).is_none());
        assert!(cache.get("c.com", RecordType::A).is_some());
    }

    #[test]
    fn overwrite_existing_record() {
        let cache = DnsCache::new();
        cache.put(a("overwrite.com", "1.1.1.1", 300));
        
        let first = cache.get("overwrite.com", RecordType::A).unwrap();
        match &first[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "1.1.1.1"),
            _ => panic!(),
        }

        cache.put(a("overwrite.com", "2.2.2.2", 300));
        
        let second = cache.get("overwrite.com", RecordType::A).unwrap();
        match &second[0].data {
            RecordData::A(ip) => assert_eq!(ip.to_string(), "2.2.2.2"),
            _ => panic!(),
        }
    }

    #[test]
    fn overwrite_with_multiple() {
        let cache = DnsCache::new();
        cache.put(a("multi.com", "1.1.1.1", 300));
        
        let records = vec![
            a("multi.com", "2.2.2.2", 300),
            a("multi.com", "3.3.3.3", 300),
        ];
        cache.put_multiple(records);

        let cached = cache.get("multi.com", RecordType::A).unwrap();
        assert_eq!(cached.len(), 2);
    }

    #[test]
    fn negative_cache_overwrites_positive() {
        let cache = DnsCache::new();
        cache.put(a("overwrite.com", "1.1.1.1", 300));
        assert!(cache.get("overwrite.com", RecordType::A).is_some());

        cache.put_negative("overwrite.com", RecordType::A, 300);
        // Should return None (negative cache)
        assert!(cache.get("overwrite.com", RecordType::A).is_none());
    }

    #[test]
    fn positive_cache_overwrites_negative() {
        let cache = DnsCache::new();
        cache.put_negative("overwrite.com", RecordType::A, 300);
        assert!(cache.get("overwrite.com", RecordType::A).is_none());

        cache.put(a("overwrite.com", "1.1.1.1", 300));
        // Should now return the positive record
        assert!(cache.get("overwrite.com", RecordType::A).is_some());
    }

    #[test]
    fn get_ns_filters_non_ns_records() {
        let cache = DnsCache::new();
        // Put A record for example.com
        cache.put(a("example.com", "1.1.1.1", 300));
        // Put NS record for example.com
        cache.put(ns("example.com", "ns.example.com", 300));

        let ns_list = cache.get_ns("example.com").unwrap();
        // Should only return NS records, not A records
        assert_eq!(ns_list, vec!["ns.example.com"]);
    }

    #[test]
    fn get_ns_empty_result_when_no_ns_in_cache() {
        let cache = DnsCache::new();
        // Only A records, no NS
        cache.put(a("example.com", "1.1.1.1", 300));
        
        assert!(cache.get_ns("example.com").is_none());
    }

    #[test]
    fn capacity_zero_handling() {
        let cache = DnsCache::with_capacity(0);
        // Should handle gracefully
        cache.put(a("test.com", "1.1.1.1", 300));
        // May or may not cache, but shouldn't panic
    }

    #[test]
    fn capacity_one_works() {
        let cache = DnsCache::with_capacity(1);
        cache.put(a("first.com", "1.1.1.1", 300));
        assert!(cache.get("first.com", RecordType::A).is_some());

        cache.put(a("second.com", "2.2.2.2", 300));
        // First should be evicted
        assert!(cache.get("first.com", RecordType::A).is_none());
        assert!(cache.get("second.com", RecordType::A).is_some());
    }

    #[test]
    fn multiple_record_types_same_domain() {
        let cache = DnsCache::new();
        cache.put(a("multi.com", "1.1.1.1", 300));
        cache.put(ns("multi.com", "ns.multi.com", 300));
        
        fn mx(name: &str, priority: u16, exchange: &str, ttl: u32) -> ResourceRecord {
            ResourceRecord {
                name: name.into(),
                record_type: RecordType::MX,
                class: RecordClass::IN,
                ttl,
                data: RecordData::MX {
                    priority,
                    exchange: exchange.into(),
                },
            }
        }
        cache.put(mx("multi.com", 10, "mx.multi.com", 300));

        assert!(cache.get("multi.com", RecordType::A).is_some());
        assert!(cache.get("multi.com", RecordType::NS).is_some());
        assert!(cache.get("multi.com", RecordType::MX).is_some());
    }

    #[test]
    fn stats_reset_on_new_cache() {
        let cache1 = DnsCache::new();
        cache1.put(a("test.com", "1.1.1.1", 300));
        cache1.get("test.com", RecordType::A);
        let (h1, m1, e1) = cache1.stats();
        assert!(h1 > 0 || m1 > 0);
        assert_eq!(e1, 0);

        let cache2 = DnsCache::new();
        let (h2, m2, e2) = cache2.stats();
        assert_eq!(h2, 0);
        assert_eq!(m2, 0);
        assert_eq!(e2, 0);
    }

    #[test]
    fn expired_entry_removed_on_get() {
        let cache = DnsCache::new();
        cache.put(a("expire.com", "1.1.1.1", 1));
        
        sleep(Duration::from_secs(2));
        
        // Getting expired entry should remove it and return None
        assert!(cache.get("expire.com", RecordType::A).is_none());
        
        // Should be removed from cache
        let (hits, misses, _) = cache.stats();
        assert_eq!(misses, 1);
        assert_eq!(hits, 0);
    }
}
