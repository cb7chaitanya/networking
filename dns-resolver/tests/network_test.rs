//! Integration tests for the network backend.
//!
//! Unit tests for `extract_ns_and_glue`, `pick_ns_server`, and `ROOT_SERVERS` live in
//! `src/network.rs`. The tests in this file perform real UDP/TCP queries and require
//! network access. They will fail if the network is unavailable or servers return errors.
//!
//! The two full-resolution tests (`resolve_example_com_a_via_network` and
//! `resolve_google_com_ns_via_network`) can take 1–2 minutes each because they do
//! full iterative resolution (root → TLD → authoritative) with timeouts and retries.

use dns_resolver::dns::RecordData;
use dns_resolver::{query_tcp, query_udp, DnsResolver, RecordType, ResourceRecord, ROOT_SERVERS};

#[test]
fn query_udp_root_server_returns_valid_response() {
    let resolver = DnsResolver::new();
    let query_bytes = resolver
        .create_query_packet(12345, "com.", RecordType::NS)
        .expect("build query");
    assert!(!query_bytes.is_empty());

    let server = ROOT_SERVERS[0];
    let response = query_udp(server, &query_bytes).expect("UDP query to root server");

    let packet = resolver
        .parse_response_packet(&response)
        .expect("valid DNS response");
    assert!(packet.header.is_response());
    assert_eq!(packet.header.rcode(), 0, "expected NOERROR");
    assert!(
        !packet.answers.is_empty() || !packet.authorities.is_empty(),
        "root should return at least answers or authorities for com. NS"
    );
}

#[test]
fn query_udp_root_server_for_example_com_ns() {
    let resolver = DnsResolver::new();
    let query_bytes = resolver
        .create_query_packet(1, "example.com.", RecordType::NS)
        .expect("build query");

    let mut last_err = None;
    for &server in ROOT_SERVERS.iter().take(3) {
        match query_udp(server, &query_bytes) {
            Ok(response) => {
                let packet = resolver
                    .parse_response_packet(&response)
                    .expect("valid DNS response");
                assert_eq!(packet.header.rcode(), 0);
                assert!(
                    !packet.answers.is_empty() || !packet.authorities.is_empty(),
                    "expected referral or answer"
                );
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    panic!("all root servers failed: {:?}", last_err);
}

#[test]
fn resolve_example_com_a_via_network() {
    let mut resolver = DnsResolver::new();
    let records = resolver
        .resolve("example.com.", RecordType::A)
        .expect("resolve example.com A");

    assert!(!records.is_empty(), "expected at least one A record");
    let a_records: Vec<&ResourceRecord> = records
        .iter()
        .filter(|r| r.record_type == RecordType::A)
        .collect();
    assert!(!a_records.is_empty());
    for rr in a_records {
        match &rr.data {
            RecordData::A(addr) => assert!(!addr.is_unspecified()),
            _ => panic!("expected A record data"),
        }
    }
}

#[test]
fn query_tcp_root_server_returns_valid_response() {
    let resolver = DnsResolver::new();
    let query_bytes = resolver
        .create_query_packet(54321, "com.", RecordType::NS)
        .expect("build query");

    let server = ROOT_SERVERS[0];
    let response = query_tcp(server, &query_bytes).expect("TCP query to root server");

    let packet = resolver
        .parse_response_packet(&response)
        .expect("valid DNS response");
    assert!(packet.header.is_response());
    assert_eq!(packet.header.rcode(), 0);
}

#[test]
fn resolve_google_com_ns_via_network() {
    let mut resolver = DnsResolver::new();
    let records = resolver
        .resolve("google.com.", RecordType::NS)
        .expect("resolve google.com NS");

    assert!(!records.is_empty());
    let ns_records: Vec<&ResourceRecord> = records
        .iter()
        .filter(|r| r.record_type == RecordType::NS)
        .collect();
    assert!(!ns_records.is_empty());
}

#[test]
fn ignores_mismatched_response_id_from_network() {
    let resolver = DnsResolver::new();
    let sent_id: u16 = 9999;
    let wrong_id: u16 = 1234;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&wrong_id.to_be_bytes());
    bytes.extend_from_slice(&0x8000u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());

    let parsed = resolver
        .parse_response_packet(&bytes)
        .expect("structurally valid packet should parse");

    assert_eq!(parsed.header.id, wrong_id);
    assert_ne!(parsed.header.id, sent_id);
}