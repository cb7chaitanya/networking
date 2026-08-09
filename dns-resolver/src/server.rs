use axum::{
    extract::State,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{CacheEntryInfo, DnsResolver};
use crate::dns::{DnsError, RecordData, RecordType};

#[derive(Clone)]
struct AppState {
    resolver: Arc<Mutex<DnsResolver>>,
}

#[derive(Serialize)]
struct CacheResponse {
    entries: Vec<CacheEntryResponse>,
    stats: CacheStats,
}

#[derive(Serialize)]
struct CacheEntryResponse {
    domain: String,
    record_type: String,
    ttl: u32,
    age: u64,
    expires_in: u64,
    is_negative: bool,
    records: Vec<String>,
}

#[derive(Serialize)]
struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    total_entries: usize,
}

#[derive(Serialize)]
struct ResolverMetricsResponse {
    resolve_calls: u64,
    cache_hits: u64,
    cache_misses: u64,
    cname_follows: u64,
    nxdomain_hits: u64,
    servfail_hits: u64,
}

fn record_data_to_string(data: &RecordData) -> String {
    match data {
        RecordData::A(ip) => ip.to_string(),
        RecordData::NS(ns) => ns.clone(),
        RecordData::CNAME(cname) => cname.clone(),
        RecordData::SOA { .. } => "SOA".to_string(),
        RecordData::MX { exchange, .. } => exchange.clone(),
        RecordData::TXT(txt) => txt.clone(),
        RecordData::AAAA(ip) => ip.to_string(),
        RecordData::PTR(ptr) => ptr.clone(),
        RecordData::Unknown(_) => "Unknown".to_string(),
    }
}

impl From<CacheEntryInfo> for CacheEntryResponse {
    fn from(info: CacheEntryInfo) -> Self {
        let records: Vec<String> = info
            .records
            .iter()
            .map(|r| record_data_to_string(&r.data))
            .collect();

        Self {
            domain: info.domain,
            record_type: format!("{:?}", info.record_type),
            ttl: info.ttl,
            age: info.created_at_secs,
            expires_in: info.expires_at_secs,
            is_negative: info.is_negative,
            records,
        }
    }
}

async fn get_cache(State(state): State<AppState>) -> impl IntoResponse {
    let resolver = state.resolver.lock().await;
    let entries = resolver.cache_entries();
    let (hits, misses, evictions) = resolver.cache_stats();
    let total_entries = entries.len();

    let response = CacheResponse {
        entries: entries.into_iter().map(CacheEntryResponse::from).collect(),
        stats: CacheStats {
            hits,
            misses,
            evictions,
            total_entries,
        },
    };

    Json(response)
}

async fn cache_stats(State(state): State<AppState>) -> impl IntoResponse {
    let resolver = state.resolver.lock().await;
    let (hits, misses, evictions) = resolver.cache_stats();
    let entries = resolver.cache_entries();

    Json(serde_json::json!({
        "hits": hits,
        "misses": misses,
        "evictions": evictions,
        "total_entries": entries.len()
    }))
}

async fn resolver_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let resolver = state.resolver.lock().await;
    let metrics = resolver.metrics().unwrap();

    Json(ResolverMetricsResponse {
        resolve_calls: metrics.resolve_calls,
        cache_hits: metrics.cache_hits,
        cache_misses: metrics.cache_misses,
        cname_follows: metrics.cname_follows,
        nxdomain_hits: metrics.nxdomain_hits,
        servfail_hits: metrics.servfail_hits,
    })
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok"
    }))
}

async fn resolve_query(State(state): State<AppState>, Json(query): Json<DnsQueryRequest>) -> impl IntoResponse {
    let mut resolver = state.resolver.lock().await;
    let record_type: RecordType = query.record_type.and_then(|rt| rt.parse().ok()).unwrap_or(RecordType::A);

    match resolver.resolve(&query.domain, record_type) {
        Ok(records) => {
            let response_records: Vec<String> = records.iter()
                .map(|r| record_data_to_string(&r.data))
                .collect();
            Json(serde_json::json!({
                "domain": query.domain,
                "record_type": format!("{:?}", record_type),
                "records": response_records,
                "cached": false
            }))
        }
        Err(e) => {
            Json(serde_json::json!({
                "domain": query.domain,
                "error": format!("{:?}", e),
                "records": [],
            }))
        }
    }
}

#[derive(serde::Deserialize)]
struct DnsQueryRequest {
    domain: String,
    record_type: Option<String>,
}

pub async fn run_http_server(resolver: Arc<Mutex<DnsResolver>>, http_port: u16) {
    let addr = SocketAddr::from(([0, 0, 0, 0], http_port));

    let app = Router::new()
        .route("/", get(health))
        .route("/cache", get(get_cache))
        .route("/cache/stats", get(cache_stats))
        .route("/metrics", get(resolver_metrics))
        .route("/resolve", axum::routing::post(resolve_query))
        .with_state(AppState { resolver });

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("HTTP API Server running on http://{}", addr);
    println!("Endpoints:");
    println!("  GET  /            - Health check");
    println!("  GET  /cache       - List all cache entries");
    println!("  GET  /cache/stats - Cache statistics");
    println!("  GET  /metrics     - Resolver metrics");
    println!("  POST /resolve     - Resolve domain (body: {{\"domain\": \"example.com\", \"record_type\": \"A\"}})");

    axum::serve(listener, app).await.unwrap();
}

pub async fn run_dns_server(resolver: Arc<Mutex<DnsResolver>>, dns_port: u16) {
    let addr = SocketAddr::from(([0, 0, 0, 0], dns_port));
    let socket = match tokio::net::UdpSocket::bind(addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Warning: Failed to bind DNS port {}: {}", dns_port, e);
            eprintln!("         DNS server will not be available.");
            eprintln!("         Use --dns-port to try a different port (e.g., --dns-port 1053)");
            return;
        }
    };
    println!("DNS Server running on udp://{}", addr);

    let mut buf = [0u8; 512];

    loop {
        let socket_clone = socket.clone();
        match socket_clone.recv_from(&mut buf).await {
            Ok((len, client_addr)) => {
                let resolver = resolver.clone();
                let socket_for_spawn = socket.clone();
                let buf_copy = buf[..len].to_vec();
                
                tokio::spawn(async move {
                    handle_dns_query(&resolver, &buf_copy, client_addr, &socket_for_spawn).await;
                });
            }
            Err(e) => {
                eprintln!("DNS recv error: {}", e);
            }
        }
    }
}

async fn handle_dns_query(
    resolver: &Arc<Mutex<DnsResolver>>,
    buf: &[u8],
    client_addr: SocketAddr,
    socket: &tokio::net::UdpSocket,
) {
    if buf.len() < 12 {
        return;
    }

    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    if qdcount == 0 {
        return;
    }

    let mut offset = 12;
    let mut qname = String::new();
    loop {
        let label_len = buf[offset];
        offset += 1;
        if label_len == 0 {
            break;
        }
        if !qname.is_empty() {
            qname.push('.');
        }
        qname.push(char::from(buf[offset]));
        qname.push(char::from(buf[offset + 1]));
        qname.push(char::from(buf[offset + 2]));
        offset += label_len as usize;
    }
    offset += 5;

    let qtype = u16::from_be_bytes([buf[offset - 5], buf[offset - 4]]);
    let record_type = RecordType::from_u16(qtype).unwrap_or(RecordType::A);

    let mut resolver_guard = resolver.lock().await;
    let response = match resolver_guard.resolve(&qname, record_type) {
        Ok(records) => build_dns_response(transaction_id, qdcount, &qname, record_type, &records, 0),
        Err(DnsError::NxDomain) => build_nxdomain_response(transaction_id, qdcount, &qname, record_type),
        Err(e) => {
            eprintln!("DNS resolve error for {}: {:?}", qname, e);
            build_servfail_response(transaction_id, qdcount, &qname, record_type)
        }
    };
    drop(resolver_guard);

    if let Ok(response) = response {
        if let Err(e) = socket.send_to(&response, client_addr).await {
            eprintln!("DNS send error: {}", e);
        }
    }
}

fn build_dns_response(
    transaction_id: u16,
    _qdcount: u16,
    qname: &str,
    qtype: RecordType,
    records: &[crate::dns::ResourceRecord],
    _rcode: u8,
) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&transaction_id.to_be_bytes());
    buf.extend_from_slice(&0x8180u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&(records.len() as u16).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    for label in qname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_u16().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    for record in records {
        if let Ok(encoded) = record_encode(record) {
            buf.extend_from_slice(&encoded);
        }
    }

    Ok(buf)
}

fn record_encode(record: &crate::dns::ResourceRecord) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::new();

    if record.name.contains('.') {
        for label in record.name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    } else {
        buf.extend_from_slice(record.name.as_bytes());
    }
    buf.push(0);

    buf.extend_from_slice(&record.record_type.to_u16().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&record.ttl.to_be_bytes());

    match &record.data {
        RecordData::A(ip) => {
            buf.extend_from_slice(&4u16.to_be_bytes());
            buf.extend_from_slice(&ip.octets());
        }
        RecordData::AAAA(ip) => {
            buf.extend_from_slice(&16u16.to_be_bytes());
            let segments = ip.segments();
            let mut bytes = Vec::with_capacity(16);
            for &seg in &segments {
                bytes.extend_from_slice(&seg.to_be_bytes());
            }
            buf.extend_from_slice(&bytes);
        }
        RecordData::NS(s) | RecordData::CNAME(s) | RecordData::PTR(s) => {
            let mut name_buf = Vec::new();
            for label in s.split('.') {
                name_buf.push(label.len() as u8);
                name_buf.extend_from_slice(label.as_bytes());
            }
            name_buf.push(0);
            buf.extend_from_slice(&(name_buf.len() as u16).to_be_bytes());
            buf.extend_from_slice(&name_buf);
        }
        RecordData::MX { exchange, .. } => {
            let mut name_buf = Vec::new();
            for label in exchange.split('.') {
                name_buf.push(label.len() as u8);
                name_buf.extend_from_slice(label.as_bytes());
            }
            name_buf.push(0);
            buf.extend_from_slice(&(name_buf.len() as u16 + 2).to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes());
            buf.extend_from_slice(&name_buf);
        }
        RecordData::TXT(txt) => {
            buf.extend_from_slice(&((txt.len() + 1) as u16).to_be_bytes());
            buf.push(txt.len() as u8);
            buf.extend_from_slice(txt.as_bytes());
        }
        _ => {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    Ok(buf)
}

fn build_nxdomain_response(transaction_id: u16, _qdcount: u16, qname: &str, qtype: RecordType) -> Result<Vec<u8>, std::io::Error> {
    build_dns_response(transaction_id, 1, qname, qtype, &[], 3)
}

fn build_servfail_response(transaction_id: u16, _qdcount: u16, qname: &str, qtype: RecordType) -> Result<Vec<u8>, std::io::Error> {
    build_dns_response(transaction_id, 1, qname, qtype, &[], 2)
}

pub async fn run_server(dns_port: u16, http_port: u16) {
    let resolver = Arc::new(Mutex::new(DnsResolver::new()));

    let dns_resolver = resolver.clone();
    let http_resolver = resolver.clone();

    let dns_handle = tokio::spawn(async move {
        run_dns_server(dns_resolver, dns_port).await;
    });

    let http_handle = tokio::spawn(async move {
        run_http_server(http_resolver, http_port).await;
    });

    println!("DNS Cache Server started");
    println!("  DNS:  udp://0.0.0.0:{}", dns_port);
    println!("  HTTP: http://0.0.0.0:{}", http_port);
    println!();

    tokio::select! {
        _ = dns_handle => {}
        _ = http_handle => {}
    }
}
