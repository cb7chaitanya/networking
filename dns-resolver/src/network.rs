//! Network backend: UDP/TCP DNS queries and root hints.

use crate::dns::{DnsError, DnsPacket, RecordData, RecordType};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Default DNS port (UDP and TCP).
pub const DNS_PORT: u16 = 53;

/// Query timeout per nameserver attempt.
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Retries on transient errors (EAGAIN, timeout).
const QUERY_RETRIES: u32 = 3;

/// Root server IPv4 addresses (IANA root hints).
/// Used to bootstrap iterative resolution.
pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

/// Returns true if the error is likely transient (retry may succeed).
fn is_transient_io_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
    ) || e.raw_os_error() == Some(35) // EAGAIN on macOS
}

/// Send a DNS query over UDP to the given server and return the raw response.
/// Retries on transient errors (EAGAIN, timeout, connection refused).
pub fn query_udp(server: &str, request: &[u8]) -> Result<Vec<u8>, DnsError> {
    let addr: SocketAddr = format!("{}:{}", server, DNS_PORT)
        .to_socket_addrs()
        .map_err(|e| DnsError::Network(e.to_string()))?
        .next()
        .ok_or_else(|| DnsError::Network("Invalid server address".into()))?;

    let mut last_err = None;
    for _ in 0..QUERY_RETRIES {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(DnsError::from)?;
        socket.set_read_timeout(Some(QUERY_TIMEOUT)).map_err(DnsError::from)?;
        socket.set_write_timeout(Some(QUERY_TIMEOUT)).map_err(DnsError::from)?;

        if let Err(e) = socket.send_to(request, addr) {
            let transient = is_transient_io_error(&e);
            last_err = Some(DnsError::from(e));
            if transient {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            return Err(last_err.unwrap());
        }

        let mut buf = [0u8; 512];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => return Ok(buf[..len].to_vec()),
            Err(e) => {
                let transient = is_transient_io_error(&e);
                last_err = Some(DnsError::from(e));
                if transient {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                return Err(last_err.unwrap());
            }
        }
    }
    Err(last_err.unwrap_or_else(|| DnsError::Network("no response".into())))
}

/// Send a DNS query over TCP (for truncated responses). RFC 1035: 2-byte length prefix.
/// Retries on transient errors.
pub fn query_tcp(server: &str, request: &[u8]) -> Result<Vec<u8>, DnsError> {
    let addr: SocketAddr = format!("{}:{}", server, DNS_PORT)
        .to_socket_addrs()
        .map_err(|e| DnsError::Network(e.to_string()))?
        .next()
        .ok_or_else(|| DnsError::Network("Invalid server address".into()))?;

    let mut last_err = None;
    for _ in 0..QUERY_RETRIES {
        let result = (|| -> Result<Vec<u8>, DnsError> {
            let mut stream = std::net::TcpStream::connect_timeout(&addr, QUERY_TIMEOUT)
                .map_err(DnsError::from)?;
            stream
                .set_read_timeout(Some(QUERY_TIMEOUT))
                .map_err(DnsError::from)?;
            stream
                .set_write_timeout(Some(QUERY_TIMEOUT))
                .map_err(DnsError::from)?;

            let len_bytes = (request.len() as u16).to_be_bytes();
            use std::io::Write;
            stream.write_all(&len_bytes).map_err(DnsError::from)?;
            stream.write_all(request).map_err(DnsError::from)?;
            stream.flush().map_err(DnsError::from)?;

            use std::io::Read;
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).map_err(DnsError::from)?;
            let response_len = u16::from_be_bytes(len_buf) as usize;
            let mut response = vec![0u8; response_len];
            stream.read_exact(&mut response).map_err(DnsError::from)?;
            Ok(response)
        })();
        match &result {
            Ok(_) => return result,
            Err(DnsError::Network(s)) if s.contains("Resource temporarily unavailable")
                || s.contains("timed out")
                || s.contains("Connection refused")
                || s.contains("Connection reset") =>
            {
                last_err = result.err();
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(DnsError::Timeout) => {
                last_err = result.err();
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return result,
        }
    }
    Err(last_err.unwrap_or_else(|| DnsError::Network("no response".into())))
}

/// Query one server: try UDP first; if response is truncated (TC=1), retry with TCP.
pub fn query(server: &str, request: &[u8]) -> Result<Vec<u8>, DnsError> {
    let response = query_udp(server, request)?;
    let packet = DnsPacket::decode(&response).map_err(|e| {
        DnsError::InvalidPacket(format!("Failed to decode UDP response: {}", e))
    })?;
    if packet.header.truncated() {
        return query_tcp(server, request);
    }
    Ok(response)
}

/// Extract nameserver hostnames from authority section and their glue A records from additional.
/// Returns a list of (ns_hostname, optional_ip). If no glue, ip is None and caller must resolve.
pub fn extract_ns_and_glue(packet: &DnsPacket) -> Vec<(String, Option<String>)> {
    use std::collections::HashMap;
    let mut glue: HashMap<String, String> = HashMap::new();
    for rr in &packet.additionals {
        if rr.record_type == RecordType::A {
            if let RecordData::A(addr) = &rr.data {
                glue.insert(rr.name.to_lowercase(), addr.to_string());
            }
        }
    }
    let mut result = Vec::new();
    for rr in &packet.authorities {
        if rr.record_type == RecordType::NS {
            if let RecordData::NS(ns) = &rr.data {
                let ns_lower = ns.to_lowercase();
                let ip = glue.get(&ns_lower).cloned();
                result.push((ns.clone(), ip));
            }
        }
    }
    result
}

/// Pick the first available server IP from (ns_name, optional_ip) list.
/// If none have glue, returns None (caller must resolve NS names).
pub fn pick_ns_server(ns_and_glue: &[(String, Option<String>)]) -> Option<String> {
    for (_, ip) in ns_and_glue {
        if let Some(addr) = ip {
            return Some(addr.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsHeader, DnsPacket, DnsQuestion, RecordClass, RecordData, RecordType, ResourceRecord};
    use std::net::Ipv4Addr;

    fn ns(name: &str, ns_host: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::NS,
            class: RecordClass::IN,
            ttl,
            data: RecordData::NS(ns_host.to_string()),
        }
    }

    fn a(name: &str, ip: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl,
            data: RecordData::A(ip.parse::<Ipv4Addr>().unwrap()),
        }
    }

    #[test]
    fn root_servers_count() {
        assert_eq!(ROOT_SERVERS.len(), 13, "IANA defines 13 root servers");
    }

    #[test]
    fn root_servers_valid_ipv4() {
        for (i, &addr) in ROOT_SERVERS.iter().enumerate() {
            let parsed: std::net::Ipv4Addr = addr
                .parse()
                .unwrap_or_else(|_| panic!("root server {} ({}) is not valid IPv4", i, addr));
            assert!(!parsed.is_unspecified(), "root server {} must not be 0.0.0.0", i);
        }
    }

    #[test]
    fn extract_ns_and_glue_with_glue() {
        let packet = DnsPacket {
            header: DnsHeader {
                id: 1,
                flags: 0x8180,
                qdcount: 1,
                ancount: 0,
                nscount: 1,
                arcount: 1,
            },
            questions: vec![DnsQuestion {
                name: "com.".to_string(),
                qtype: RecordType::NS,
                qclass: RecordClass::IN,
            }],
            answers: vec![],
            authorities: vec![ns("com.", "a.gtld-servers.net.", 3600)],
            additionals: vec![a("a.gtld-servers.net.", "192.5.6.30", 3600)],
        };
        let result = extract_ns_and_glue(&packet);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "a.gtld-servers.net.");
        assert_eq!(result[0].1.as_deref(), Some("192.5.6.30"));
    }

    #[test]
    fn extract_ns_and_glue_without_glue() {
        let packet = DnsPacket {
            header: DnsHeader {
                id: 1,
                flags: 0x8180,
                qdcount: 1,
                ancount: 0,
                nscount: 1,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
            authorities: vec![ns("com.", "a.gtld-servers.net.", 3600)],
            additionals: vec![],
        };
        let result = extract_ns_and_glue(&packet);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "a.gtld-servers.net.");
        assert_eq!(result[0].1, None);
    }

    #[test]
    fn extract_ns_and_glue_multiple_ns_and_glue() {
        let packet = DnsPacket {
            header: DnsHeader {
                id: 1,
                flags: 0x8180,
                qdcount: 1,
                ancount: 0,
                nscount: 2,
                arcount: 2,
            },
            questions: vec![],
            answers: vec![],
            authorities: vec![
                ns("example.com.", "ns1.example.com.", 3600),
                ns("example.com.", "ns2.example.com.", 3600),
            ],
            additionals: vec![
                a("ns1.example.com.", "192.0.2.1", 3600),
                a("ns2.example.com.", "192.0.2.2", 3600),
            ],
        };
        let result = extract_ns_and_glue(&packet);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "ns1.example.com.");
        assert_eq!(result[0].1.as_deref(), Some("192.0.2.1"));
        assert_eq!(result[1].0, "ns2.example.com.");
        assert_eq!(result[1].1.as_deref(), Some("192.0.2.2"));
    }

    #[test]
    fn extract_ns_and_glue_glue_case_insensitive() {
        let packet = DnsPacket {
            header: DnsHeader {
                id: 1,
                flags: 0x8180,
                qdcount: 0,
                ancount: 0,
                nscount: 1,
                arcount: 1,
            },
            questions: vec![],
            answers: vec![],
            authorities: vec![ns("com.", "A.GTLD-SERVERS.NET.", 3600)],
            additionals: vec![a("a.gtld-servers.net.", "192.5.6.30", 3600)],
        };
        let result = extract_ns_and_glue(&packet);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1.as_deref(), Some("192.5.6.30"));
    }

    #[test]
    fn pick_ns_server_with_glue() {
        let ns_and_glue = vec![
            ("ns1.example.com.".to_string(), None),
            ("ns2.example.com.".to_string(), Some("192.0.2.2".to_string())),
        ];
        assert_eq!(pick_ns_server(&ns_and_glue), Some("192.0.2.2".to_string()));
    }

    #[test]
    fn pick_ns_server_without_glue() {
        let ns_and_glue = vec![
            ("ns1.example.com.".to_string(), None),
            ("ns2.example.com.".to_string(), None),
        ];
        assert_eq!(pick_ns_server(&ns_and_glue), None);
    }

    #[test]
    fn pick_ns_server_empty() {
        let ns_and_glue: Vec<(String, Option<String>)> = vec![];
        assert_eq!(pick_ns_server(&ns_and_glue), None);
    }

    #[test]
    fn pick_ns_server_first_glue_wins() {
        let ns_and_glue = vec![
            ("ns1.example.com.".to_string(), Some("192.0.2.1".to_string())),
            ("ns2.example.com.".to_string(), Some("192.0.2.2".to_string())),
        ];
        assert_eq!(pick_ns_server(&ns_and_glue), Some("192.0.2.1".to_string()));
    }

    #[test]
    fn dns_port_is_53() {
        assert_eq!(DNS_PORT, 53);
    }
}
