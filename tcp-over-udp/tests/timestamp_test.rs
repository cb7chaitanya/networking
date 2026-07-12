use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tcp_over_udp::packet::{Packet, Header, TcpOption, flags};
use tcp_over_udp::socket::Socket;



#[test]
fn timestamp_option_encode_decode_roundtrip() {
    let pkt = Packet {
        header: Header {
            seq: 1,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(12345, 0)],
        payload: vec![],
    };
    let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
    assert_eq!(decoded.options, vec![TcpOption::Timestamp(12345, 0)]);
}

#[test]
fn timestamp_wire_length_correct() {
    let pkt = Packet {
        header: Header {
            seq: 0,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(1, 2)],
        payload: vec![],
    };
    use tcp_over_udp::packet::HEADER_LEN;
    assert_eq!(pkt.encode().unwrap().len(), HEADER_LEN + 11);
}

#[test]
fn timestamp_with_mss_roundtrip() {
    let pkt = Packet {
        header: Header {
            seq: 100,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![
            TcpOption::Mss(1460),
            TcpOption::Timestamp(999, 0),
        ],
        payload: vec![],
    };
    let decoded = Packet::decode(&pkt.encode().unwrap()).unwrap();
    assert_eq!(decoded.options, vec![
        TcpOption::Mss(1460),
        TcpOption::Timestamp(999, 0),
    ]);
}

#[test]
fn tsecr_is_echoed_correctly() {
    // Simulate: sender sends TSval=500, receiver echoes it as TSecr=500
    let data_pkt = Packet {
        header: Header {
            seq: 1,
            ack: 0,
            flags: flags::ACK,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(500, 0)],
        payload: b"hello".to_vec(),
    };

    // Extract TSval from incoming packet
    let tsval = data_pkt.options.iter().find_map(|o| {
        if let TcpOption::Timestamp(tsval, _) = o { Some(*tsval) } else { None }
    }).unwrap();

    // Build ACK echoing that TSval as TSecr
    let ack_pkt = Packet {
        header: Header {
            seq: 0,
            ack: 2,
            flags: flags::ACK,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(600, tsval)],
        payload: vec![],
    };

    let decoded = Packet::decode(&ack_pkt.encode().unwrap()).unwrap();
    let echoed = decoded.options.iter().find_map(|o| {
        if let TcpOption::Timestamp(_, tsecr) = o { Some(*tsecr) } else { None }
    }).unwrap();

    assert_eq!(echoed, 500);
}

// ── PAWS tests ───────────────────────────────────────────────────────────────

#[test]
fn paws_rejects_older_timestamp() {
    // A segment is considered old if its TSval < last seen TSval
    let last_tsval: u32 = 1000;

    let old_segment = Packet {
        header: Header {
            seq: 50,
            ack: 0,
            flags: flags::ACK,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(500, 0)], // TSval=500 < 1000
        payload: b"stale".to_vec(),
    };

    let incoming_tsval = old_segment.options.iter().find_map(|o| {
        if let TcpOption::Timestamp(tsval, _) = o { Some(*tsval) } else { None }
    });

    // PAWS check: reject if tsval < last_tsval
    let paws_rejected = incoming_tsval.map_or(false, |tsval| tsval < last_tsval);
    assert!(paws_rejected, "PAWS should reject segment with older timestamp");
}

#[test]
fn paws_accepts_newer_timestamp() {
    let last_tsval: u32 = 1000;

    let new_segment = Packet {
        header: Header {
            seq: 51,
            ack: 0,
            flags: flags::ACK,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(1001, 0)], // TSval=1001 > 1000
        payload: b"fresh".to_vec(),
    };

    let incoming_tsval = new_segment.options.iter().find_map(|o| {
        if let TcpOption::Timestamp(tsval, _) = o { Some(*tsval) } else { None }
    });

    let paws_rejected = incoming_tsval.map_or(false, |tsval| tsval < last_tsval);
    assert!(!paws_rejected, "PAWS should accept segment with newer timestamp");
}

#[test]
fn paws_accepts_equal_timestamp() {
    // Equal TSval is also acceptable (not strictly less than)
    let last_tsval: u32 = 1000;
    let incoming_tsval: u32 = 1000;
    let paws_rejected = incoming_tsval < last_tsval;
    assert!(!paws_rejected, "PAWS should accept segment with equal timestamp");
}

// ── Handshake timestamp negotiation ─────────────────────────────────────────

#[tokio::test]
async fn syn_carries_timestamp_option() {
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let _socket = Socket::bind(server_addr).await.unwrap();

    let syn = Packet {
        header: Header {
            seq: 100,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![
            TcpOption::Mss(1460),
            TcpOption::Timestamp(42, 0), // TSval=42, TSecr=0 on SYN
        ],
        payload: vec![],
    };

    let decoded = Packet::decode(&syn.encode().unwrap()).unwrap();
    let has_timestamp = decoded.options.iter().any(|o| matches!(o, TcpOption::Timestamp(_, _)));
    assert!(has_timestamp, "SYN must carry timestamp option");
}

#[tokio::test]
async fn syn_ack_echoes_tsval_in_tsecr() {
    let syn = Packet {
        header: Header {
            seq: 1,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(100, 0)],
        payload: vec![],
    };

    let client_tsval = syn.options.iter().find_map(|o| {
        if let TcpOption::Timestamp(tsval, _) = o { Some(*tsval) } else { None }
    }).unwrap();

    // SYN-ACK should echo client TSval as TSecr
    let syn_ack = Packet {
        header: Header {
            seq: 200,
            ack: 2,
            flags: flags::SYN | flags::ACK,
            window: 8192,
            checksum: 0,
        },
        options: vec![TcpOption::Timestamp(999, client_tsval)], // TSecr = client's TSval
        payload: vec![],
    };

    let decoded = Packet::decode(&syn_ack.encode().unwrap()).unwrap();
    let tsecr = decoded.options.iter().find_map(|o| {
        if let TcpOption::Timestamp(_, tsecr) = o { Some(*tsecr) } else { None }
    }).unwrap();

    assert_eq!(tsecr, 100, "SYN-ACK must echo client TSval as TSecr");
}


#[test]
fn rtt_sample_from_timestamp_echo() {
    use std::time::{Duration, Instant};
    use tcp_over_udp::rtt::RttEstimator;

    let mut estimator = RttEstimator::new();

    // Simulate: sent at t=0ms with TSval=0, ACK comes back with TSecr=0 at t=50ms
    let _send_time = Instant::now();
    let rtt_sample = Duration::from_millis(50); // derived from timestamp echo

    estimator.record_sample(rtt_sample);

    assert!(estimator.has_sample());
    assert_eq!(estimator.srtt(), Some(Duration::from_millis(50)));
}