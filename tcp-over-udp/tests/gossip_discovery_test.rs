use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use gossip_membership::node::NodeConfig;
use gossip_membership::runner::{run_node, Node};
use gossip_membership::transport::Transport;
use tcp_over_udp::connection::Connection;
use tcp_over_udp::discovery::GossipDiscovery;
use tcp_over_udp::socket::Socket;
use tokio::sync::oneshot;

async fn bind_membership() -> Transport {
    Transport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind failed")
}

#[tokio::test]
async fn tcp_client_connects_via_gossip_discovery() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cfg = NodeConfig::fast();

    let t1 = bind_membership().await;
    let t2 = bind_membership().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let app1 = n1.app_state.clone();
    let app2 = n2.app_state.clone();
    let n1_id = n1.id;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let gossip1 = tokio::spawn(run_node(n1, rx1));
    let gossip2 = tokio::spawn(run_node(n2, rx2));

    let server_socket = Socket::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("server bind");
    let server_addr = server_socket.local_addr;

    let server = tokio::spawn(async move {
        let mut conn = Connection::accept(server_socket).await.expect("accept");
        let payload = conn.recv().await.expect("recv");
        assert_eq!(payload, b"Ping!");
        conn.send(b"Pong!").await.expect("send");
        conn.close().await.expect("close");
    });

    let announcer = GossipDiscovery::new(app1, "echo");
    announcer.advertise(n1_id, server_addr);

    tokio::time::sleep(Duration::from_millis(700)).await;

    let discovery = GossipDiscovery::new(app2, "echo");
    let client_socket = Socket::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("client bind");
    let mut client = Connection::connect_via_discovery(client_socket, &discovery)
        .await
        .expect("connect via gossip");

    client.send(b"Ping!").await.expect("send");
    let reply = client.recv().await.expect("recv");
    assert_eq!(reply, b"Pong!");
    client.close().await.expect("close");

    server.await.unwrap();
    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = gossip1.await.unwrap();
    let _ = gossip2.await.unwrap();
}
