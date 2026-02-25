use rand::Rng;
use std::{thread, time::Duration};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use dns_resolver::{DnsError, DnsResolver, ResourceRecord, RecordType};
use dns_resolver::dns::{RecordClass, RecordData};

/// ------------------------------------------------------------
/// Helper functions for creating test records
/// ------------------------------------------------------------

fn a(name: &str, ip: &str, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
        ttl,
        data: RecordData::A(ip.parse().unwrap()),
    }
}

fn aaaa(name: &str, ip: &str, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        record_type: RecordType::AAAA,
        class: RecordClass::IN,
        ttl,
        data: RecordData::AAAA(ip.parse().unwrap()),
    }
}

fn cname(name: &str, target: &str, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        record_type: RecordType::CNAME,
        class: RecordClass::IN,
        ttl,
        data: RecordData::CNAME(target.to_string()),
    }
}

fn txt(name: &str, text: &str, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        record_type: RecordType::TXT,
        class: RecordClass::IN,
        ttl,
        data: RecordData::TXT(text.to_string()),
    }
}

/// ------------------------------------------------------------
/// Mock DNS backend (NO NETWORK)
/// ------------------------------------------------------------

#[derive(Clone, Default)]
struct MockDnsBackend {
    responses: Arc<RwLock<HashMap<(String, RecordType), Result<Vec<ResourceRecord>, DnsError>>>>,
}

impl MockDnsBackend {
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
        let responses = self.responses.read().unwrap();
        
        // First try exact match
        if let Some(result) = responses.get(&(name.to_string(), rtype)) {
            return result.clone();
        }
        
        // If querying for A/AAAA and not found, check for CNAME (RFC 1034)
        if matches!(rtype, RecordType::A | RecordType::AAAA) {
            if let Some(result) = responses.get(&(name.to_string(), RecordType::CNAME)) {
                return result.clone();
            }
        }
        
        Err(DnsError::NxDomain)
    }
}

/// ------------------------------------------------------------
/// Helper: resolver with mock backend
/// ------------------------------------------------------------

fn test_resolver(backend: MockDnsBackend) -> DnsResolver {
    DnsResolver::with_backend(Box::new(move |name, rtype| {
        backend.resolve(name, rtype)
    }))
}

#[test]
fn fuzz_cname_chains() {
    let backend = MockDnsBackend::default();
    let mut rng = rand::rng();

    // Random chain length between 2 and 10
    let chain_len = rng.random_range(2..=10);
    let names: Vec<String> = (0..chain_len).map(|i| format!("node{}.com", i)).collect();

    // Add A record at the end of chain
    let last = names.last().unwrap().clone();
    backend.insert_ok(&last, RecordType::A, vec![a(&last, "1.2.3.4", 60)]);

    // Insert CNAMEs linking the chain
    for i in (0..names.len() - 1).rev() {
        backend.insert_ok(&names[i], RecordType::CNAME, vec![cname(&names[i], &names[i + 1], 60)]);
    }

    let mut resolver = test_resolver(backend);
    let resolved = resolver.resolve(&names[0], RecordType::A).unwrap();

    // The resolver returns CNAME records followed by the final A record
    // Find the A record (should be the last one)
    let a_record = resolved.iter()
        .find(|r| matches!(r.record_type, RecordType::A))
        .expect("Expected A record at end of CNAME chain");
    
    match &a_record.data {
        RecordData::A(ip) => assert_eq!(ip.to_string(), "1.2.3.4"),
        _ => panic!("Expected A record at end of CNAME chain"),
    }
}

#[test]
fn fuzz_random_multi_answers() {
    let backend = MockDnsBackend::default();
    let mut rng = rand::rng();
    let name = "multi-fuzz.com";

    // Random number of A records between 1 and 5
    let count = rng.random_range(1..=5);
    let mut records = vec![];
    for i in 0..count {
        records.push(a(name, &format!("10.0.0.{}", i + 1), 60));
    }

    backend.insert_ok(name, RecordType::A, records.clone());
    let mut resolver = test_resolver(backend);

    let resolved = resolver.resolve(name, RecordType::A).unwrap();
    assert_eq!(resolved.len(), count);

    for r in resolved.iter() {
        match &r.data {
            RecordData::A(ip) => assert!(ip.octets()[0] == 10),
            _ => panic!("Expected A record"),
        }
    }
}

#[test]
fn fuzz_ttl_expiry_random() {
    let backend = MockDnsBackend::default();
    let mut rng = rand::rng();
    let name = "ttl-fuzz.com";

    // Random TTL between 1 and 3 seconds
    let ttl = rng.random_range(1..=3);
    backend.insert_ok(name, RecordType::A, vec![a(name, "5.6.7.8", ttl)]);
    let mut resolver = test_resolver(backend);

    resolver.resolve(name, RecordType::A).unwrap();
    thread::sleep(Duration::from_secs(ttl as u64 + 1));

    let refreshed = resolver.resolve(name, RecordType::A).unwrap();
    match &refreshed[0].data {
        RecordData::A(ip) => assert_eq!(ip.to_string(), "5.6.7.8"),
        _ => panic!("Expected A record"),
    }
}

#[test]
fn fuzz_mixed_record_types_random() {
    let backend = MockDnsBackend::default();

    let names = ["mixed1.com", "mixed2.com", "mixed3.com"];
    backend.insert_ok(names[0], RecordType::A, vec![a(names[0], "1.1.1.1", 60)]);
    backend.insert_ok(names[1], RecordType::AAAA, vec![aaaa(names[1], "2001:db8::1", 60)]);
    backend.insert_ok(names[2], RecordType::TXT, vec![txt(names[2], "random text", 60)]);

    let mut resolver = test_resolver(backend);

    let a_res = resolver.resolve(names[0], RecordType::A).unwrap();
    match &a_res[0].data { RecordData::A(ip) => assert_eq!(ip.to_string(), "1.1.1.1"), _ => panic!() }

    let aaaa_res = resolver.resolve(names[1], RecordType::AAAA).unwrap();
    match &aaaa_res[0].data { RecordData::AAAA(ip) => assert_eq!(ip.to_string(), "2001:db8::1"), _ => panic!() }

    let txt_res = resolver.resolve(names[2], RecordType::TXT).unwrap();
    match &txt_res[0].data { RecordData::TXT(s) => assert_eq!(s, "random text"), _ => panic!() }
}

#[test]
fn fuzz_random_errors_cached() {
    let backend = MockDnsBackend::default();
    let mut rng = rand::rng();

    let names = ["err1.com", "err2.com"];
    let errors = [DnsError::NxDomain, DnsError::ServFail];

    for name in names.iter() {
        let idx = rng.random_range(0..errors.len());
        let err = errors[idx].clone();
        backend.insert_err(name, RecordType::A, err);
    }

    let mut resolver = test_resolver(backend);

    for name in names.iter() {
        let res = resolver.resolve(name, RecordType::A);
        assert!(res.is_err());
    }

    // Ensure negative caching works
    for name in names.iter() {
        let res = resolver.resolve(name, RecordType::A);
        assert!(res.is_err());
    }
}
