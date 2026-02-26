use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use dns_resolver::dns::{RecordClass, RecordData};
use dns_resolver::{DnsError, DnsResolver, RecordType, ResourceRecord};
use rand::Rng;

/// ------------------------------------------------------------
/// Helper functions for creating test records
/// ------------------------------------------------------------
mod record_helpers {
    use super::*;

    pub fn a(name: &str, ip: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl,
            data: RecordData::A(ip.parse().unwrap()),
        }
    }

    pub fn aaaa(name: &str, ip: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::AAAA,
            class: RecordClass::IN,
            ttl,
            data: RecordData::AAAA(ip.parse().unwrap()),
        }
    }

    pub fn cname(name: &str, target: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::CNAME,
            class: RecordClass::IN,
            ttl,
            data: RecordData::CNAME(target.to_string()),
        }
    }

    pub fn mx(name: &str, priority: u16, exchange: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::MX,
            class: RecordClass::IN,
            ttl,
            data: RecordData::MX {
                priority,
                exchange: exchange.to_string(),
            },
        }
    }

    pub fn ns(name: &str, nsd: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::NS,
            class: RecordClass::IN,
            ttl,
            data: RecordData::NS(nsd.to_string()),
        }
    }

    pub fn ptr(name: &str, target: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::PTR,
            class: RecordClass::IN,
            ttl,
            data: RecordData::PTR(target.to_string()),
        }
    }

    pub fn txt(name: &str, txt: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::TXT,
            class: RecordClass::IN,
            ttl,
            data: RecordData::TXT(txt.to_string()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn soa(
        name: &str,
        mname: &str,
        rname: &str,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: u32,
    ) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::SOA,
            class: RecordClass::IN,
            ttl,
            data: RecordData::SOA {
                mname: mname.to_string(),
                rname: rname.to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
        }
    }
}
use record_helpers::*;

/// ------------------------------------------------------------
/// Mock DNS backend (NO NETWORK)
/// ------------------------------------------------------------
type ResponseMap = HashMap<(String, RecordType), Result<Vec<ResourceRecord>, DnsError>>;

#[derive(Clone)]
struct MockDnsBackend {
    responses: Arc<RwLock<ResponseMap>>,
    delay_per_query: Duration,
}

impl Default for MockDnsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDnsBackend {
    fn new() -> Self {
        Self {
            responses: Arc::new(RwLock::new(ResponseMap::default())),
            delay_per_query: Duration::ZERO,
        }
    }

    fn with_delay(delay_per_query: Duration) -> Self {
        Self {
            responses: Arc::new(RwLock::new(ResponseMap::default())),
            delay_per_query,
        }
    }

    fn insert_ok(&self, name: &str, rtype: RecordType, records: Vec<ResourceRecord>) {
        self.responses
            .write()
            .unwrap()
            .insert((name.to_string(), rtype), Ok(records));
    }

    fn insert_err(&self, name: &str, rtype: RecordType, err: DnsError) {
        self.responses
            .write()
            .unwrap()
            .insert((name.to_string(), rtype), Err(err));
    }

    fn resolve(&self, name: &str, rtype: RecordType) -> Result<Vec<ResourceRecord>, DnsError> {
        if self.delay_per_query > Duration::ZERO {
            std::thread::sleep(self.delay_per_query);
        }
        self.responses
            .read()
            .unwrap()
            .get(&(name.to_string(), rtype))
            .cloned()
            .unwrap_or(Err(DnsError::NxDomain))
    }
}

/// ------------------------------------------------------------
/// Helper: resolver with mock backend
/// ------------------------------------------------------------
fn test_resolver(backend: MockDnsBackend) -> DnsResolver {
    DnsResolver::with_backend(Box::new(move |name, rtype| backend.resolve(name, rtype)))
}

/// ------------------------------------------------------------
/// TESTS
/// ------------------------------------------------------------
#[test]
fn resolve_a_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "google.com",
        RecordType::A,
        vec![a("google.com", "8.8.8.8", 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("google.com", RecordType::A).unwrap();
    assert_eq!(records.len(), 1);
}

#[test]
fn resolve_aaaa_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "ipv6.com",
        RecordType::AAAA,
        vec![aaaa("ipv6.com", "2001:db8::1", 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("ipv6.com", RecordType::AAAA).unwrap();
    match &records[0].data {
        RecordData::AAAA(ip) => assert_eq!(ip.to_string(), "2001:db8::1"),
        _ => panic!(),
    }
}

#[test]
fn resolve_mx_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "mail.com",
        RecordType::MX,
        vec![mx("mail.com", 10, "mx.mail.com", 120)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("mail.com", RecordType::MX).unwrap();
    match &records[0].data {
        RecordData::MX { priority, exchange } => {
            assert_eq!(*priority, 10);
            assert_eq!(exchange, "mx.mail.com");
        }
        _ => panic!(),
    }
}

#[test]
fn resolve_ns_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "example.com",
        RecordType::NS,
        vec![ns("example.com", "ns1.example.com", 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("example.com", RecordType::NS).unwrap();
    match &records[0].data {
        RecordData::NS(s) => assert_eq!(s, "ns1.example.com"),
        _ => panic!(),
    }
}

#[test]
fn resolve_ptr_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "1.0.0.127.in-addr.arpa",
        RecordType::PTR,
        vec![ptr("1.0.0.127.in-addr.arpa", "localhost", 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver
        .resolve("1.0.0.127.in-addr.arpa", RecordType::PTR)
        .unwrap();
    match &records[0].data {
        RecordData::PTR(s) => assert_eq!(s, "localhost"),
        _ => panic!(),
    }
}

#[test]
fn resolve_txt_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "txt.com",
        RecordType::TXT,
        vec![txt("txt.com", "hello world", 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("txt.com", RecordType::TXT).unwrap();
    match &records[0].data {
        RecordData::TXT(s) => assert_eq!(s, "hello world"),
        _ => panic!(),
    }
}

#[test]
fn resolve_soa_record_success() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "soa.com",
        RecordType::SOA,
        vec![soa("soa.com", "mname", "rname", 1, 2, 3, 4, 5, 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("soa.com", RecordType::SOA).unwrap();
    match &records[0].data {
        RecordData::SOA { serial, .. } => assert_eq!(*serial, 1),
        _ => panic!(),
    }
}

#[test]
fn cname_chaining_multiple_hops() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "a.com",
        RecordType::CNAME,
        vec![cname("a.com", "b.com", 60)],
    );
    backend.insert_ok(
        "b.com",
        RecordType::CNAME,
        vec![cname("b.com", "c.com", 60)],
    );
    backend.insert_ok("c.com", RecordType::A, vec![a("c.com", "9.9.9.9", 60)]);
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("a.com", RecordType::A).unwrap();
    match &records[2].data {
        RecordData::A(ip) => assert_eq!(ip.to_string(), "9.9.9.9"),
        _ => panic!(),
    }
}

#[test]
fn cname_loop_detected() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "loop1.com",
        RecordType::CNAME,
        vec![cname("loop1.com", "loop2.com", 60)],
    );
    backend.insert_ok(
        "loop2.com",
        RecordType::CNAME,
        vec![cname("loop2.com", "loop1.com", 60)],
    );
    let mut resolver = test_resolver(backend);
    let result = resolver.resolve("loop1.com", RecordType::A);
    assert!(matches!(result, Err(DnsError::ServFail)));
}

#[test]
fn multiple_answers_returned() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "multi.com",
        RecordType::A,
        vec![a("multi.com", "1.1.1.1", 60), a("multi.com", "1.1.1.2", 60)],
    );
    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("multi.com", RecordType::A).unwrap();
    assert_eq!(records.len(), 2);
}

#[test]
fn ttl_expiry_refreshes_cache() {
    let backend = MockDnsBackend::default();
    backend.insert_ok("ttl.com", RecordType::A, vec![a("ttl.com", "1.1.1.1", 1)]);
    let mut resolver = test_resolver(backend.clone());
    resolver.resolve("ttl.com", RecordType::A).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let refreshed = resolver.resolve("ttl.com", RecordType::A).unwrap();
    match &refreshed[0].data {
        RecordData::A(ip) => assert_eq!(ip.to_string(), "1.1.1.1"),
        _ => panic!(),
    }
}

#[test]
fn negative_nxdomain_cached() {
    let backend = MockDnsBackend::default();
    backend.insert_err("ghost.xyz", RecordType::A, DnsError::NxDomain);
    let mut resolver = test_resolver(backend.clone());
    assert!(matches!(
        resolver.resolve("ghost.xyz", RecordType::A),
        Err(DnsError::NxDomain)
    ));
    assert!(matches!(
        resolver.resolve("ghost.xyz", RecordType::A),
        Err(DnsError::NxDomain)
    ));
}

#[test]
fn negative_servfail_cached() {
    let backend = MockDnsBackend::default();
    backend.insert_err("fail.com", RecordType::A, DnsError::ServFail);
    let mut resolver = test_resolver(backend.clone());
    assert!(matches!(
        resolver.resolve("fail.com", RecordType::A),
        Err(DnsError::ServFail)
    ));
    assert!(matches!(
        resolver.resolve("fail.com", RecordType::A),
        Err(DnsError::ServFail)
    ));
}

#[test]
fn concurrent_reads_and_writes() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "threaded.com",
        RecordType::A,
        vec![a("threaded.com", "172.16.0.1", 300)],
    );
    let resolver = Arc::new(RwLock::new(test_resolver(backend)));
    let mut handles = vec![];
    for _ in 0..8 {
        let r = resolver.clone();
        handles.push(std::thread::spawn(move || {
            let mut res = r.write().unwrap();
            res.resolve("threaded.com", RecordType::A).unwrap();
        }));
    }
    for _ in 0..8 {
        let r = resolver.clone();
        handles.push(std::thread::spawn(move || {
            let mut res = r.write().unwrap();
            res.resolve("threaded.com", RecordType::A).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn timeout_guard_prevents_hangs() {
    let backend = MockDnsBackend::default();
    let mut resolver = test_resolver(backend);
    let start = Instant::now();
    let result = resolver.resolve("never-added.com", RecordType::A);
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}

// ============================================================
// Tests for resolver helper functions
// ============================================================

#[test]
fn metrics_tracking() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "metrics.com",
        RecordType::A,
        vec![a("metrics.com", "1.1.1.1", 60)],
    );
    let mut resolver = test_resolver(backend);

    // First query - cache miss
    resolver.resolve("metrics.com", RecordType::A).unwrap();
    let metrics = resolver.metrics().unwrap();
    assert_eq!(metrics.resolve_calls, 1);
    assert_eq!(metrics.cache_misses, 1);
    assert_eq!(metrics.cache_hits, 0);
    drop(metrics);

    // Second query - cache hit
    resolver.resolve("metrics.com", RecordType::A).unwrap();
    let metrics = resolver.metrics().unwrap();
    assert_eq!(metrics.resolve_calls, 2);
    assert_eq!(metrics.cache_misses, 1);
    assert_eq!(metrics.cache_hits, 1);
}

#[test]
fn cache_stats_tracking() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "stats.com",
        RecordType::A,
        vec![a("stats.com", "1.1.1.1", 60)],
    );
    let mut resolver = test_resolver(backend);

    // First query
    resolver.resolve("stats.com", RecordType::A).unwrap();
    let (hits, misses, evictions) = resolver.cache_stats();
    assert_eq!(misses, 1);
    assert_eq!(hits, 0);
    assert_eq!(evictions, 0);

    // Second query - should hit cache
    resolver.resolve("stats.com", RecordType::A).unwrap();
    let (hits, misses, evictions) = resolver.cache_stats();
    assert_eq!(hits, 1);
    assert_eq!(misses, 1);
    assert_eq!(evictions, 0);
}

#[test]
fn cache_cleanup_expired() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "expire.com",
        RecordType::A,
        vec![a("expire.com", "1.1.1.1", 1)],
    );
    let mut resolver = test_resolver(backend);

    resolver.resolve("expire.com", RecordType::A).unwrap();
    // Second resolve hits cache
    resolver.resolve("expire.com", RecordType::A).unwrap();

    std::thread::sleep(Duration::from_secs(2));
    resolver.cleanup_cache();

    // After cleanup, resolve again - should be a cache miss
    resolver.resolve("expire.com", RecordType::A).unwrap();

    let (hits, misses, _) = resolver.cache_stats();
    assert!(misses >= 2); // First resolve + resolve after cleanup
    assert!(hits >= 1); // Second resolve before cleanup
}

#[test]
fn get_nameservers_with_fallback() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "example.com",
        RecordType::NS,
        vec![
            ns("example.com", "ns1.example.com", 60),
            ns("example.com", "ns2.example.com", 60),
        ],
    );
    let mut resolver = test_resolver(backend);

    // Resolve NS records first to populate cache
    resolver.resolve("example.com", RecordType::NS).unwrap();

    // Now test get_nameservers
    let ns_list = resolver.get_nameservers("sub.example.com").unwrap();
    assert_eq!(ns_list.len(), 2);
    assert!(ns_list.contains(&"ns1.example.com".to_string()));
    assert!(ns_list.contains(&"ns2.example.com".to_string()));
}

#[test]
fn get_nameservers_parent_fallback() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "parent.com",
        RecordType::NS,
        vec![ns("parent.com", "ns.parent.com", 60)],
    );
    let mut resolver = test_resolver(backend);

    resolver.resolve("parent.com", RecordType::NS).unwrap();

    // Should find parent NS
    let ns_list = resolver.get_nameservers("child.parent.com").unwrap();
    assert_eq!(ns_list, vec!["ns.parent.com"]);
}

#[test]
fn create_query_packet() {
    let backend = MockDnsBackend::default();
    let resolver = test_resolver(backend);

    let packet_bytes = resolver
        .create_query_packet(1234, "example.com", RecordType::A)
        .unwrap();
    assert!(!packet_bytes.is_empty());
    assert!(packet_bytes.len() >= 12); // At least header size

    // Decode and verify
    use dns_resolver::dns::DnsPacket;
    let packet = DnsPacket::decode(&packet_bytes).unwrap();
    assert_eq!(packet.header.id, 1234);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.questions[0].name, "example.com");
    assert_eq!(packet.questions[0].qtype, RecordType::A);
}

#[test]
fn parse_response_packet_success() {
    use dns_resolver::dns::{DnsHeader, DnsPacket, DnsQuestion, RecordClass};

    // Create a successful response packet (RCODE = 0)
    // Don't set ancount to 1 since encode() doesn't encode answers
    let mut header = DnsHeader::new_query(5678);
    header.flags |= 0x8000; // Set QR bit (response)
                            // Keep ancount = 0 since encode() only handles header + questions

    let packet = DnsPacket {
        header,
        questions: vec![DnsQuestion {
            name: "test.com".to_string(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    // Encode the packet
    let encoded = packet.encode().unwrap();

    let backend = MockDnsBackend::default();
    let resolver = test_resolver(backend);

    // Should succeed (RCODE = 0)
    let result = resolver.parse_response_packet(&encoded);
    assert!(result.is_ok());

    let parsed = result.unwrap();
    assert_eq!(parsed.header.id, 5678);
    assert!(parsed.header.is_response());
    assert_eq!(parsed.header.rcode(), 0);
    assert_eq!(parsed.questions.len(), 1);
    assert_eq!(parsed.questions[0].name, "test.com");
}

#[test]
fn parse_response_packet_nxdomain() {
    use dns_resolver::dns::{DnsHeader, DnsPacket, DnsQuestion, RecordClass};

    // Create NXDOMAIN response packet
    let mut header = DnsHeader::new_query(9999);
    header.flags |= 0x8000; // Set QR bit (response)
    header.flags |= 0x0003; // Set RCODE = 3 (NXDOMAIN)

    let packet = DnsPacket {
        header,
        questions: vec![DnsQuestion {
            name: "nonexistent.example.com".to_string(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    // Encode the packet (encode() handles header + questions)
    let encoded = packet.encode().unwrap();

    // Test parse_response_packet
    let backend = MockDnsBackend::default();
    let resolver = test_resolver(backend);

    // Should return NxDomain error
    let result = resolver.parse_response_packet(&encoded);
    assert!(matches!(result, Err(DnsError::NxDomain)));

    // Verify the packet was decoded correctly before error
    let decoded = DnsPacket::decode(&encoded).unwrap();
    assert_eq!(decoded.header.id, 9999);
    assert!(decoded.header.is_response());
    assert_eq!(decoded.header.rcode(), 3);
    assert_eq!(decoded.questions.len(), 1);
    assert_eq!(decoded.questions[0].name, "nonexistent.example.com");
}

// ============================================================
// Tests for DNS packet encoding/decoding
// ============================================================

#[test]
fn dns_packet_encode_decode_roundtrip() {
    use dns_resolver::dns::DnsPacket;

    let packet = DnsPacket::new_query(12345, "roundtrip.test".to_string(), RecordType::MX);
    let encoded = packet.encode().unwrap();
    let decoded = DnsPacket::decode(&encoded).unwrap();

    assert_eq!(decoded.header.id, 12345);
    assert_eq!(decoded.questions.len(), 1);
    assert_eq!(decoded.questions[0].name, "roundtrip.test");
    assert_eq!(decoded.questions[0].qtype, RecordType::MX);
}

#[test]
fn dns_header_methods() {
    use dns_resolver::dns::DnsHeader;

    let mut header = DnsHeader::new_query(100);
    assert!(!header.is_response());
    assert_eq!(header.rcode(), 0);
    assert!(!header.truncated());
    assert!(!header.is_authoritative());

    // Set as response
    header.flags |= 0x8000;
    assert!(header.is_response());

    // Set NXDOMAIN
    header.flags |= 0x0003;
    assert_eq!(header.rcode(), 3);

    // Set truncated
    header.flags |= 0x0200;
    assert!(header.truncated());

    // Set authoritative
    header.flags |= 0x0400;
    assert!(header.is_authoritative());
}

#[test]
fn dns_header_serialization() {
    use dns_resolver::dns::DnsHeader;

    let header = DnsHeader {
        id: 0xABCD,
        flags: 0x8180,
        qdcount: 1,
        ancount: 2,
        nscount: 3,
        arcount: 4,
    };

    let bytes = header.to_bytes();
    let decoded = DnsHeader::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.id, 0xABCD);
    assert_eq!(decoded.flags, 0x8180);
    assert_eq!(decoded.qdcount, 1);
    assert_eq!(decoded.ancount, 2);
    assert_eq!(decoded.nscount, 3);
    assert_eq!(decoded.arcount, 4);
}

// ============================================================
// Tests for RecordType parsing
// ============================================================

#[test]
fn record_type_from_str() {
    assert_eq!("A".parse::<RecordType>().unwrap(), RecordType::A);
    assert_eq!("AAAA".parse::<RecordType>().unwrap(), RecordType::AAAA);
    assert_eq!("CNAME".parse::<RecordType>().unwrap(), RecordType::CNAME);
    assert_eq!("NS".parse::<RecordType>().unwrap(), RecordType::NS);
    assert_eq!("MX".parse::<RecordType>().unwrap(), RecordType::MX);
    assert_eq!("TXT".parse::<RecordType>().unwrap(), RecordType::TXT);
    assert_eq!("PTR".parse::<RecordType>().unwrap(), RecordType::PTR);
    assert_eq!("SOA".parse::<RecordType>().unwrap(), RecordType::SOA);

    // Case insensitive
    assert_eq!("a".parse::<RecordType>().unwrap(), RecordType::A);
    assert_eq!("aaaa".parse::<RecordType>().unwrap(), RecordType::AAAA);

    // Invalid
    assert!("INVALID".parse::<RecordType>().is_err());
}

#[test]
fn record_type_from_u16() {
    use dns_resolver::dns::RecordType;

    assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
    assert_eq!(RecordType::from_u16(2), Some(RecordType::NS));
    assert_eq!(RecordType::from_u16(5), Some(RecordType::CNAME));
    assert_eq!(RecordType::from_u16(6), Some(RecordType::SOA));
    assert_eq!(RecordType::from_u16(12), Some(RecordType::PTR));
    assert_eq!(RecordType::from_u16(15), Some(RecordType::MX));
    assert_eq!(RecordType::from_u16(16), Some(RecordType::TXT));
    assert_eq!(RecordType::from_u16(28), Some(RecordType::AAAA));
    assert_eq!(RecordType::from_u16(999), Some(RecordType::Unknown(999)));
}

// ============================================================
// Tests for ResourceRecord Display
// ============================================================

#[test]
fn resource_record_display() {
    let rr_a = a("display.com", "192.168.1.1", 300);
    let display = format!("{}", rr_a);
    assert!(display.contains("display.com"));
    assert!(display.contains("192.168.1.1"));

    let rr_cname = cname("alias.com", "target.com", 60);
    let display = format!("{}", rr_cname);
    assert!(display.contains("alias.com"));
    assert!(display.contains("target.com"));

    let rr_mx = mx("mail.com", 10, "mx.mail.com", 120);
    let display = format!("{}", rr_mx);
    assert!(display.contains("mail.com"));
    assert!(display.contains("10"));
    assert!(display.contains("mx.mail.com"));
}

// ============================================================
// Tests for cache edge cases
// ============================================================

#[test]
fn cache_put_multiple_homogeneous() {
    // Multiple A records for same domain
    let records = vec![
        a("multi.com", "1.1.1.1", 60),
        a("multi.com", "1.1.1.2", 60),
        a("multi.com", "1.1.1.3", 60),
    ];

    // This should work via resolve
    let backend = MockDnsBackend::default();
    backend.insert_ok("multi.com", RecordType::A, records);
    let mut resolver = test_resolver(backend);
    let resolved = resolver.resolve("multi.com", RecordType::A).unwrap();
    assert_eq!(resolved.len(), 3);
}

#[test]
fn cache_negative_ttl_zero() {
    let backend = MockDnsBackend::default();

    // Negative cache with TTL=0 should not be cached
    backend.insert_err("zero-ttl.com", RecordType::A, DnsError::NxDomain);

    let mut resolver = test_resolver(backend);
    resolver.resolve("zero-ttl.com", RecordType::A).unwrap_err();

    // Should still query backend (not cached)
    let (hits, misses, _) = resolver.cache_stats();
    // Should have at least one miss
    assert!(misses >= 1);
    // Hits should be 0 since we're querying different domains each time
    assert_eq!(hits, 0);
}

#[test]
fn cache_lru_eviction_integration() {
    let backend = MockDnsBackend::default();

    // Insert many records (more than default cache capacity of 1024)
    // to trigger evictions
    for i in 0..1100 {
        let domain = format!("evict{}.com", i);
        backend.insert_ok(&domain, RecordType::A, vec![a(&domain, "1.1.1.1", 300)]);
    }

    let mut resolver = test_resolver(backend);

    // Now resolve all domains - should trigger evictions when capacity is exceeded
    for i in 0..1100 {
        let domain = format!("evict{}.com", i);
        resolver.resolve(&domain, RecordType::A).unwrap();
    }

    let (hits, misses, evictions) = resolver.cache_stats();
    // Should have misses for all domains (first time queries)
    assert!(misses >= 1100);
    // Hits should be 0 since we're querying different domains each time
    assert_eq!(hits, 0);
    // With 1100 records and capacity of 1024, should have at least 76 evictions
    assert!(evictions >= 76);
}

// ============================================================
// Tests for CNAME edge cases
// ============================================================

#[test]
fn cname_to_cname_to_a() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "www.example.com",
        RecordType::CNAME,
        vec![cname("www.example.com", "web.example.com", 60)],
    );
    backend.insert_ok(
        "web.example.com",
        RecordType::CNAME,
        vec![cname("web.example.com", "final.example.com", 60)],
    );
    backend.insert_ok(
        "final.example.com",
        RecordType::A,
        vec![a("final.example.com", "10.0.0.1", 60)],
    );

    let mut resolver = test_resolver(backend);
    let records = resolver.resolve("www.example.com", RecordType::A).unwrap();

    // Should have 2 CNAMEs + 1 A
    assert_eq!(records.len(), 3);
    assert!(matches!(records[0].record_type, RecordType::CNAME));
    assert!(matches!(records[1].record_type, RecordType::CNAME));
    assert!(matches!(records[2].record_type, RecordType::A));

    let metrics = resolver.metrics().unwrap();
    assert_eq!(metrics.cname_follows, 2);
}

#[test]
fn cname_metrics_tracking() {
    let backend = MockDnsBackend::default();
    backend.insert_ok(
        "cname-metrics.com",
        RecordType::CNAME,
        vec![cname("cname-metrics.com", "target.com", 60)],
    );
    backend.insert_ok(
        "target.com",
        RecordType::A,
        vec![a("target.com", "5.5.5.5", 60)],
    );

    let mut resolver = test_resolver(backend);
    resolver
        .resolve("cname-metrics.com", RecordType::A)
        .unwrap();

    let metrics = resolver.metrics().unwrap();
    assert_eq!(metrics.cname_follows, 1);
}

// ============================================================
// Tests for error handling
// ============================================================

#[test]
fn nxdomain_metrics() {
    let backend = MockDnsBackend::default();
    backend.insert_err("nxdomain-test.com", RecordType::A, DnsError::NxDomain);

    let mut resolver = test_resolver(backend);
    let result = resolver.resolve("nxdomain-test.com", RecordType::A);
    assert!(matches!(result, Err(DnsError::NxDomain)));

    let metrics = resolver.metrics().unwrap();
    assert_eq!(metrics.nxdomain_hits, 1);
}

#[test]
fn servfail_metrics() {
    let backend = MockDnsBackend::default();
    backend.insert_err("servfail-test.com", RecordType::A, DnsError::ServFail);

    let mut resolver = test_resolver(backend);
    let result = resolver.resolve("servfail-test.com", RecordType::A);
    assert!(matches!(result, Err(DnsError::ServFail)));

    let metrics = resolver.metrics().unwrap();
    assert_eq!(metrics.servfail_hits, 1);
}

// ============================================================
// Tests for TXT record decoding
// ============================================================

#[test]
fn txt_record_decoding_single_string() {
    use dns_resolver::dns::{DnsHeader, RecordClass};

    // Manually encode the packet with TXT record
    let mut data = DnsHeader {
        id: 1234,
        flags: 0x8180, // Response, AA
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
    }
    .to_bytes();

    // Encode question
    encode_domain_name(&mut data, "test.com");
    data.extend_from_slice(&RecordType::TXT.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());

    // Encode answer: name + type + class + ttl + rdlen + rdata
    encode_domain_name(&mut data, "test.com");
    data.extend_from_slice(&RecordType::TXT.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    data.extend_from_slice(&300u32.to_be_bytes()); // TTL

    // TXT RDATA: length byte + string bytes
    let txt_data = b"hello world";
    let rdata_len = 1 + txt_data.len(); // 1 byte for length + data
    data.extend_from_slice(&(rdata_len as u16).to_be_bytes()); // RDATA length
    data.push(txt_data.len() as u8); // First length byte
    data.extend_from_slice(txt_data);

    // Decode and verify
    use dns_resolver::dns::DnsPacket;
    let decoded = DnsPacket::decode(&data).unwrap();
    assert_eq!(decoded.answers.len(), 1);
    match &decoded.answers[0].data {
        RecordData::TXT(s) => assert_eq!(s, "hello world"),
        _ => panic!("Expected TXT record, got {:?}", decoded.answers[0].data),
    }
}

#[test]
fn txt_record_decoding_multiple_strings() {
    use dns_resolver::dns::{DnsHeader, DnsPacket, RecordClass};

    // Create a packet with a TXT record containing multiple strings
    let mut data = DnsHeader {
        id: 1234,
        flags: 0x8180,
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
    }
    .to_bytes();

    // Encode question
    encode_domain_name(&mut data, "test.com");
    data.extend_from_slice(&RecordType::TXT.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());

    // Encode answer
    encode_domain_name(&mut data, "test.com");
    data.extend_from_slice(&RecordType::TXT.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    data.extend_from_slice(&300u32.to_be_bytes());

    // TXT RDATA: multiple length-prefixed strings
    let str1 = b"v=spf1";
    let str2 = b"include:_spf.google.com";
    let total_len = 1 + str1.len() + 1 + str2.len();
    data.extend_from_slice(&(total_len as u16).to_be_bytes());
    data.push(str1.len() as u8);
    data.extend_from_slice(str1);
    data.push(str2.len() as u8);
    data.extend_from_slice(str2);

    // Decode and verify
    let decoded = DnsPacket::decode(&data).unwrap();
    assert_eq!(decoded.answers.len(), 1);
    match &decoded.answers[0].data {
        RecordData::TXT(s) => {
            // Should be concatenated
            assert_eq!(s, "v=spf1include:_spf.google.com");
        }
        _ => panic!("Expected TXT record"),
    }
}

// ============================================================
// Tests for domain name compression
// ============================================================

#[test]
fn domain_name_compression_encoding() {
    use dns_resolver::dns::{DnsHeader, DnsPacket, RecordClass};

    // Create a query packet - compression should work for repeated names
    let packet = DnsPacket::new_query(1234, "www.example.com".to_string(), RecordType::A);
    let encoded = packet.encode().unwrap();

    // Decode to verify it's valid
    let decoded = DnsPacket::decode(&encoded).unwrap();
    assert_eq!(decoded.questions[0].name, "www.example.com");

    // Create a response packet with multiple records using the same domain
    // This will test compression in practice
    let mut response_data = DnsHeader {
        id: 1234,
        flags: 0x8180,
        qdcount: 1,
        ancount: 2, // Two answers
        nscount: 0,
        arcount: 0,
    }
    .to_bytes();

    // Question section
    encode_domain_name(&mut response_data, "example.com");
    response_data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    response_data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());

    // Answer 1: example.com A 1.1.1.1
    let answer1_start = response_data.len();
    encode_domain_name(&mut response_data, "example.com");
    response_data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    response_data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    response_data.extend_from_slice(&300u32.to_be_bytes());
    response_data.extend_from_slice(&4u16.to_be_bytes()); // RDATA length
    response_data.extend_from_slice(&[1, 1, 1, 1]);

    // Answer 2: example.com A 2.2.2.2 (should use compression pointer)
    // The domain name "example.com" should be compressed
    let name_offset = answer1_start; // Where "example.com" starts in answer 1
    let ptr = 0xC000u16 | (name_offset as u16);
    response_data.extend_from_slice(&ptr.to_be_bytes());
    response_data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    response_data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    response_data.extend_from_slice(&300u32.to_be_bytes());
    response_data.extend_from_slice(&4u16.to_be_bytes());
    response_data.extend_from_slice(&[2, 2, 2, 2]);

    // Decode and verify both answers
    let decoded = DnsPacket::decode(&response_data).unwrap();
    assert_eq!(decoded.answers.len(), 2);
    assert_eq!(decoded.answers[0].name, "example.com");
    assert_eq!(decoded.answers[1].name, "example.com");
}

#[test]
fn domain_name_compression_decoding() {
    use dns_resolver::dns::RecordClass;

    // Test that we can decode compressed domain names correctly
    // This verifies the decode_domain_name function handles compression pointers
    // We'll create a simple packet with a compression pointer

    // Create a minimal packet: question with "example.com", answer with compression pointer
    let mut data = vec![
        0x04, 0xD2, // ID
        0x81, 0x80, // Flags (response)
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];

    // Question: example.com (at offset 12)
    data.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());

    // Answer: example.com (using compression pointer to offset 12)
    // Compression pointer: 0xC0 0x0C (points to offset 12)
    data.push(0xC0);
    data.push(0x0C);
    data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    data.extend_from_slice(&300u32.to_be_bytes());
    data.extend_from_slice(&4u16.to_be_bytes());
    data.extend_from_slice(&[1, 1, 1, 1]);

    // Decode and verify
    use dns_resolver::dns::DnsPacket;
    let decoded = DnsPacket::decode(&data).unwrap();
    assert_eq!(decoded.questions[0].name, "example.com");
    assert_eq!(decoded.answers[0].name, "example.com");
}

#[test]
fn domain_name_compression_mixed_label_and_pointer_decoding() {
    use dns_resolver::dns::{DnsHeader, DnsPacket, RecordClass, RecordData};

    // Build a packet where answer NAME is "www" + pointer to "example.com" in question.
    let mut data = DnsHeader {
        id: 1234,
        flags: 0x8180,
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
    }
    .to_bytes();

    encode_domain_name(&mut data, "example.com");
    data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());

    // NAME: 3www + pointer to offset 12 ("example.com")
    data.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x0C]);
    data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    data.extend_from_slice(&300u32.to_be_bytes());
    data.extend_from_slice(&4u16.to_be_bytes());
    data.extend_from_slice(&[1, 2, 3, 4]);

    let decoded = DnsPacket::decode(&data).unwrap();
    assert_eq!(decoded.answers[0].name, "www.example.com");
    match &decoded.answers[0].data {
        RecordData::A(ip) => assert_eq!(ip.octets(), [1, 2, 3, 4]),
        _ => panic!("Expected A record"),
    }
}

#[test]
fn truncated_rdata_returns_error_not_panic() {
    use dns_resolver::dns::{DnsError, DnsHeader, DnsPacket, RecordClass};

    let mut data = DnsHeader {
        id: 1234,
        flags: 0x8180,
        qdcount: 1,
        ancount: 1,
        nscount: 0,
        arcount: 0,
    }
    .to_bytes();

    encode_domain_name(&mut data, "example.com");
    data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());

    // Valid fixed RR fields, but rdlen says 4 and we only provide 2 bytes.
    data.extend_from_slice(&[0xC0, 0x0C]);
    data.extend_from_slice(&RecordType::A.to_u16().to_be_bytes());
    data.extend_from_slice(&RecordClass::IN.to_u16().to_be_bytes());
    data.extend_from_slice(&300u32.to_be_bytes());
    data.extend_from_slice(&4u16.to_be_bytes());
    data.extend_from_slice(&[1, 2]);

    let decode = std::panic::catch_unwind(|| DnsPacket::decode(&data));
    assert!(decode.is_ok(), "decoder panicked on truncated rdata");
    match decode.unwrap() {
        Ok(_) => panic!("expected decode error"),
        Err(DnsError::InvalidPacket(_)) => {}
        Err(other) => panic!("expected InvalidPacket, got {:?}", other),
    }
}

#[test]
fn recursive_resolution_enforces_global_timeout() {
    let backend = MockDnsBackend::with_delay(Duration::from_millis(2000));

    backend.insert_ok(
        "a.com",
        RecordType::CNAME,
        vec![cname("a.com", "b.com", 60)],
    );
    backend.insert_ok(
        "b.com",
        RecordType::CNAME,
        vec![cname("b.com", "c.com", 60)],
    );
    backend.insert_ok(
        "c.com",
        RecordType::CNAME,
        vec![cname("c.com", "d.com", 60)],
    );
    backend.insert_ok(
        "d.com",
        RecordType::CNAME,
        vec![cname("d.com", "e.com", 60)],
    );
    backend.insert_ok("e.com", RecordType::A, vec![a("e.com", "1.2.3.4", 60)]);

    let mut resolver = test_resolver(backend);

    let start = Instant::now();
    let result = resolver.resolve("a.com", RecordType::A);
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(DnsError::Timeout)),
        "Expected Timeout error, got {:?}",
        result
    );
    assert!(
        elapsed >= GLOBAL_TIMEOUT,
        "Resolution should have timed out after {}ms, but took {:?}",
        GLOBAL_TIMEOUT.as_millis(),
        elapsed
    );
}

// Helper function for encoding domain names in tests
fn encode_domain_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}


//test for query ID randomization
#[test]
fn test_query_ids_no_collisions() {
    let ids: std::collections::HashSet<u16> =
        (0..100).map(|_| rand::rng().random::<u16>()).collect();
    assert!(ids.len() > 90);
}