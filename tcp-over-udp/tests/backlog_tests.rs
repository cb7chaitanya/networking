use std::net::{SocketAddr, IpAddr, Ipv4Addr};

use tcp_over_udp::listener::Listener;
use tcp_over_udp::packet::{Packet, Header, flags};
use tcp_over_udp::socket::Socket;

#[tokio::test]
async fn backlog_is_enforced() {
let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
let socket = Socket::bind(server_addr).await.unwrap();

let mut listener = Listener::new(socket, 5); // backlog = 5

for i in 0..20 {
    let addr: SocketAddr = format!("127.0.0.1:{}", 10000 + i).parse().unwrap();
    let syn = Packet {
        header: Header {
            seq: i,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![],
        payload: vec![],
    };

    listener.handle_syn(syn, addr);
}

assert_eq!(listener.syn_queue_len(), 5);


}
#[tokio::test]
async fn syn_flood_does_not_exceed_backlog() {
let server_addr = "127.0.0.1:0".parse().unwrap();
let socket = Socket::bind(server_addr).await.unwrap();


let mut listener = Listener::new(socket, 10);

for i in 0..1000 {
    let addr: SocketAddr = format!("127.0.0.1:{}", 10000 + i).parse().unwrap();
    let syn = Packet {
        header: Header {
            seq: i,
            ack: 0,
            flags: flags::SYN,
            window: 8192,
            checksum: 0,
        },
        options: vec![],
        payload: vec![],
    };

    listener.handle_syn(syn, addr);
}

assert!(listener.syn_queue_len() <= 10);

}

#[tokio::test]
async fn accept_returns_established_connection() {
let server_addr = "127.0.0.1:0".parse().unwrap();
let socket = Socket::bind(server_addr).await.unwrap();

let mut listener = Listener::new(socket, 5);

let client = "127.0.0.1:40000".parse().unwrap();

let syn = Packet {
    header: Header {
        seq: 100,
        ack: 0,
        flags: flags::SYN,
        window: 8192,
        checksum: 0,
    },
    options: vec![],
    payload: vec![],
};

listener.handle_syn(syn, client);

let ack = Packet {
    header: Header {
        seq: 101,
        ack: 1,
        flags: flags::ACK,
        window: 8192,
        checksum: 0,
    },
    options: vec![],
    payload: vec![],
};

listener.handle_ack(ack, client);

let conn = listener.accept().await.unwrap();

assert_eq!(conn.state, tcp_over_udp::state::ConnectionState::Established);

}
