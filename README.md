# networking

Networking and distributed systems protocols implemented from scratch in Rust. Each project takes a canonical networking problem and builds a working implementation from first principles, following RFCs and papers rather than textbook summaries.

## Projects

### [tcp-over-udp](tcp-over-udp/)

A complete TCP-like reliable transport stack running over UDP sockets. Implements the 3-way handshake, sliding window (Go-Back-N + Selective Repeat), SACK, TCP Reno congestion control, RTT estimation (RFC 6298), flow control with persist timer, Nagle's algorithm, and full connection teardown — all verified against a pluggable fault-injection simulator.

**~8,000 lines | 200+ tests | 16 modules**

### [dns-resolver](dns-resolver/)

An iterative DNS resolver that starts from the 13 IANA root servers and walks the hierarchy (root → TLD → authoritative) to resolve domain names. Handles binary packet encoding/decoding (RFC 1035), name compression, CNAME chains, UDP with TCP fallback, and TTL-based LRU caching with negative cache support.

**~2,300 lines | CI/CD pipeline**

### [gossip-membership](gossip-membership/)

A SWIM-style gossip membership protocol where nodes discover peers, detect failures via direct + indirect probes, and maintain a consistent cluster view through epidemic dissemination. Features ChaCha20-Poly1305 encryption, anti-entropy full-table sync, adaptive fanout, rate limiting, and a Prometheus/Grafana observability stack.

**~6,600 lines | 266+ tests | property tests | fuzz targets | benchmarks**

### [raft-consensus](raft-consensus/)

A full implementation of the Raft consensus algorithm covering the complete paper and dissertation: leader election, PreVote, log replication, joint consensus membership changes, leadership transfer, ReadIndex, snapshotting, and crash recovery via a segmented CRC32-framed WAL. The consensus core is a pure deterministic state machine driven by a seeded in-process simulator for testing and an async TCP transport for production. Includes a Prometheus/Grafana observability stack with 22+ metrics and a 27-panel dashboard.

**~15,000 lines | 319+ tests | 3 fuzz targets | benchmarks | Prometheus metrics**

## Building

Each project is a standalone Cargo package — no workspace. Build and test independently:

```bash
cd tcp-over-udp && cargo test
cd dns-resolver && cargo test
cd gossip-membership && cargo test
cd raft-consensus && cargo test
```

## Structure

```
networking/
├── tcp-over-udp/          # TCP over UDP (transport layer)
├── dns-resolver/          # Iterative DNS resolver (application layer)
├── gossip-membership/     # SWIM gossip protocol (distributed systems)
└── raft-consensus/        # Raft consensus algorithm (distributed consensus)
```
