use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use dns_resolver::dns::{RecordClass, RecordData};
use dns_resolver::{DnsResolver, RecordType, ResourceRecord};
use gossip_membership::node::NodeConfig;
use gossip_membership::runner::{run_node, Node};
use gossip_membership::transport::Transport;
use tokio::sync::oneshot;

async fn bind_local() -> Transport {
    Transport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind failed")
}

#[tokio::test]
async fn resolver_reads_dns_cache_entries_from_gossip() {
    let cfg = NodeConfig::fast();

    let t1 = bind_local().await;
    let t2 = bind_local().await;
    let addr1 = t1.local_addr;
    let addr2 = t2.local_addr;

    let n1 = Node::new(t1, cfg.clone(), &[addr2]);
    let n2 = Node::new(t2, cfg.clone(), &[addr1]);
    let app1 = n1.app_state.clone();
    let app2 = n2.app_state.clone();

    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_hits_clone = backend_hits.clone();

    let mut resolver1 = DnsResolver::with_backend(Box::new(move |domain, record_type| {
        backend_hits_clone.fetch_add(1, Ordering::Relaxed);
        assert_eq!(domain, "example.com");
        assert_eq!(record_type, RecordType::A);
        Ok(vec![ResourceRecord {
            name: domain.to_string(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl: 30,
            data: RecordData::A(Ipv4Addr::new(1, 1, 1, 1)),
        }])
    }))
    .with_distributed_cache(app1);

    let mut resolver2 = DnsResolver::with_backend(Box::new(|_, _| {
        panic!("resolver2 backend should not be called when gossip cache is warm")
    }))
    .with_distributed_cache(app2);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let h1 = tokio::spawn(run_node(n1, rx1));
    let h2 = tokio::spawn(run_node(n2, rx2));

    let seeded = resolver1.resolve("example.com", RecordType::A).unwrap();
    assert_eq!(seeded.len(), 1);
    assert_eq!(backend_hits.load(Ordering::Relaxed), 1);

    tokio::time::sleep(Duration::from_millis(700)).await;

    let answer = resolver2.resolve("example.com", RecordType::A).unwrap();
    assert_eq!(answer.len(), 1);
    assert!(matches!(answer[0].data, RecordData::A(addr) if addr == Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        1,
        "only resolver1 should have queried the backend"
    );

    let _ = tx1.send(());
    let _ = tx2.send(());
    let _ = h1.await.unwrap();
    let _ = h2.await.unwrap();
}
