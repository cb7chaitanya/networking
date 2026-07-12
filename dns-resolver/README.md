# DNS Resolver

An iterative DNS resolver implemented from scratch in Rust. Starting from the 13 IANA root server addresses — hardcoded, no operating system configuration — it walks the DNS hierarchy (root → TLD → authoritative) to resolve any domain name, following referrals and glue records at each level exactly as a real resolver would.

Built to understand what `getaddrinfo(3)` actually does: not just "send a query to 8.8.8.8" but the full referral chain that makes the distributed DNS system work.

**~2,300 lines | 50 tests | 4 modules**

---

## How DNS Resolution Works

DNS is a distributed, hierarchical database. No single server knows the answer to every query; instead, each level of the hierarchy knows where to direct you next.

```
You: "What is the IP address of www.example.com?"

  ┌─────────────────────────────────────────────────────────────┐
  │  Root servers (hardcoded 13 IPs)                            │
  │  "I don't know, but .com is handled by these NS servers:"   │
  │  a.gtld-servers.net → 192.5.6.30                            │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │  .com TLD servers                                            │
  │  "I don't know, but example.com is handled by:"             │
  │  ns1.example.com → 205.251.196.1  (glue record)             │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │  Authoritative servers for example.com                       │
  │  "www.example.com → 93.184.216.34"                          │
  └─────────────────────────────────────────────────────────────┘
```

The complication: sometimes glue records are missing. If a TLD server says "the authoritative NS for example.com is `ns1.example.com`" but doesn't include `ns1.example.com`'s IP, the resolver must first resolve `ns1.example.com` — a recursive sub-resolution — before it can continue. This implementation handles both the glue-present and glue-absent paths.

UDP is the default transport at each step (port 53, 4-second timeout, 3 retries). If a response has the TC (truncated) bit set, the resolver falls back to TCP and re-fetches the full response.

---

## Architecture

```
src/
├── dns.rs       Packet encoding/decoding (RFC 1035)
│                  DnsPacket, DnsQuestion, ResourceRecord
│                  RecordType: A NS CNAME SOA PTR MX TXT AAAA
│                  RecordClass: IN CH HS
│                  Name compression: pointers, labels, encoding
│                  DnsError
│
├── network.rs   Transport layer
│                  ROOT_SERVERS: 13 IANA root IP addresses
│                  query_udp(): UDP send, 3 retries, 4s timeout
│                  query_tcp(): TCP fallback for truncated responses
│                  query(): UDP-first, TCP on TC bit
│                  extract_ns_and_glue(): pull NS + A records from authority/additional
│                  pick_ns_server(): prefer cached IPs, else resolve NS hostnames
│
├── resolver.rs  Iterative resolution engine
│                  DnsResolver: cache + metrics + optional mock backend
│                  resolve(): main entry point, handles CNAME chains
│                  iterative_resolve(): walk root → TLD → authoritative
│                  BackendFn: pluggable backend for unit testing
│                  ResolverMetrics: resolve calls, cache hits, CNAME follows, NXDOMAIN/SERVFAIL
│
├── cache.rs     LRU cache with TTL expiry
│                  DnsCache: Arc<RwLock<CacheInner>>
│                  Positive entries: Vec<ResourceRecord> + expiry Instant
│                  Negative entries: NXDOMAIN caching with TTL
│                  LRU eviction via VecDeque order maintenance
│                  Cache key: (name, RecordType) — normalised to lowercase
│                  Heterogeneous RRset guard (panics on mixed types, by design)
│
└── main.rs      CLI
```

---

## Features

| Feature | RFC | Notes |
|---|---|---|
| Iterative resolution from root | 1034 | Starts from 13 hardcoded root IPs |
| Binary DNS packet encode/decode | 1035 | Questions, answers, authority, additional |
| Name compression (pointers) | 1035 §4.1.4 | Both encode and decode |
| UDP queries with retry | 1035 | 4s timeout, 3 retries per nameserver |
| TCP fallback on truncation | 1035 §4.2.2 | Triggered by TC bit in response |
| CNAME chain following | 1034 | Up to 16 hops (loop guard) |
| Glue record extraction | 1034 | Uses additional section to avoid extra round-trips |
| NS hostname resolution | 1034 | Recursive sub-resolution when glue is absent |
| TTL-based LRU cache | 1034 | Positive and negative (NXDOMAIN) entries |
| Thread-safe cache | — | `Arc<RwLock<>>`, safe to share across threads |
| Mock backend | — | `BackendFn` for deterministic unit tests |

**Supported record types:** A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, Unknown(u16)

---

## Usage

```bash
cargo build --release

# Resolve an A record (default)
cargo run -- example.com

# Specify record type
cargo run -- example.com NS
cargo run -- example.com MX
cargo run -- example.com AAAA
cargo run -- gmail.com TXT

# Non-existent domain
cargo run -- this-domain-does-not-exist-12345.com A
```

Example output:

```
$ cargo run -- google.com A
google.com 300 IN A 142.250.191.14

$ cargo run -- google.com NS
google.com 21599 IN NS ns1.google.com.
google.com 21599 IN NS ns2.google.com.
google.com 21599 IN NS ns3.google.com.
google.com 21599 IN NS ns4.google.com.
```

---

## DNS Packet Wire Format

All integers are big-endian (network byte order), as specified by RFC 1035.

```
DNS Message:
┌─────────────────────────────────┐
│  Header (12 bytes)               │
│  ID(2) FLAGS(2) QDCOUNT(2)       │
│  ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)│
├─────────────────────────────────┤
│  Question section                │
│  QNAME (labels) QTYPE(2) QCLASS(2)│
├─────────────────────────────────┤
│  Answer section    (ANCOUNT RRs) │
├─────────────────────────────────┤
│  Authority section (NSCOUNT RRs) │
├─────────────────────────────────┤
│  Additional section(ARCOUNT RRs) │
└─────────────────────────────────┘

Resource Record:
NAME (labels or pointer) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(RDLENGTH)

Name encoding (§4.1.4):
  Label:   [len: u8][bytes: len]  (len < 64)
  Pointer: [0xC0 | hi][lo]        (14-bit offset from start of message)
  End:     [0x00]
```

The pointer mechanism allows names that appear multiple times in a message to be encoded once and referenced by offset — critical for keeping responses small over UDP.

---

## Testing

```bash
cargo test                  # 50 unit tests (no network required)
cargo test -- --ignored     # live network tests (require internet)
```

| Module | Tests | What they cover |
|---|---|---|
| `cache.rs` | 39 | TTL expiry, LRU eviction, negative caching, NXDOMAIN, thread safety, capacity limits |
| `network.rs` | 11 | Root server list, glue extraction, NS picking logic |
| Network (ignored) | ~5 | Live queries against real nameservers (flaky in CI) |

The resolver uses a `BackendFn` trait object so unit tests can inject deterministic responses without any network I/O:

```rust
let resolver = DnsResolver::with_backend(Box::new(|name, rtype| {
    if name == "example.com" && rtype == RecordType::A {
        Ok(vec![/* synthetic ResourceRecord */])
    } else {
        Err(DnsError::NxDomain)
    }
}));
```

Live network tests are marked `#[ignore]` and run separately to avoid CI flakiness. The CI pipeline uses `continue-on-error: true` for the live test job.

---

## Error Handling

| Error | RCODE | Meaning |
|---|---|---|
| `NxDomain` | 3 | Domain does not exist |
| `ServFail` | 2 | Nameserver returned SERVFAIL |
| `Timeout` | — | No response within deadline |
| `Network(msg)` | — | I/O error (UDP send, TCP connect) |
| `Decode(msg)` | — | Malformed DNS response packet |
| `MaxDepth` | — | CNAME chain exceeded 16 hops |

---

## Dependencies

```toml
anyhow    = "1.0"   # error context in main
rand      = "0.9"   # random nameserver selection within each tier
thiserror = "1.0"   # DnsError derive
```
