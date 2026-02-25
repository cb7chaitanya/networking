# DNS Resolver

A DNS resolver implementation in Rust built from scratch. This resolver performs **iterative** DNS resolution starting from the 13 root servers and follows the DNS hierarchy (root → TLD → authoritative) to resolve domain names.

## Features (MVP Scope)

### Core Features

- **Binary DNS packet encoder/decoder**: Full implementation of DNS packet encoding and decoding (including resource records) according to RFC 1035, with name compression
- **UDP-based queries (port 53)**: Sends DNS queries over UDP to nameservers; **TCP fallback** when the response is truncated (TC bit set)
- **Iterative resolution**: Starts from IANA root hints, follows NS referrals and glue records, and resolves NS hostnames when glue is not provided
- **TTL-based in-memory cache**: Caches DNS records (including referral NS and glue) with TTL-based expiration
- **Proper error handling**: Handles NXDOMAIN (domain not found), SERVFAIL (server failure), and timeouts

### Supported Record Types

- A (IPv4 address)
- NS (Name Server)
- CNAME (Canonical Name)
- PTR (Pointer)
- MX (Mail Exchange)
- TXT (Text)
- SOA (Start of Authority)

## Out of Scope (Not Implemented)

The following features are explicitly **not** included in this MVP:

- **DNSSEC**: No DNS security extensions
- **EDNS0**: No Extended DNS (EDNS) support
- **DoH / DoT**: No DNS over HTTPS or DNS over TLS
- **IPv6 transport**: Resolution uses IPv4 for nameserver communication; AAAA records are supported and returned when requested

## Usage

```bash
# Build the project
cargo build --release

# Resolve a domain (defaults to A record)
cargo run -- example.com

# Resolve a specific record type
cargo run -- example.com NS
cargo run -- example.com MX
cargo run -- example.com CNAME
```

## How It Works

1. **Query Construction**: Creates a DNS query packet with the requested domain and record type (with name compression).
2. **Iterative Resolution**:
   - Starts with the 13 root server IPs (root hints)
   - Sends the query (UDP; TCP if response is truncated)
   - On referral (authority NS + optional glue A), uses glue or resolves NS hostnames and queries the next level
   - Caches NS and A records from referrals for reuse
3. **Response Handling**:
   - Parses DNS response packets
   - Handles CNAME records by following the chain
   - Returns final answers or appropriate error codes
4. **Caching**: Stores resolved records with TTL-based expiration to avoid redundant queries

## Architecture

- `src/dns.rs`: DNS packet structures, encoding, and decoding (questions and resource records)
- `src/network.rs`: UDP/TCP queries, root hints, and helpers to extract NS/glue from responses
- `src/resolver.rs`: Iterative resolution logic (network) and optional mock backend for tests
- `src/cache.rs`: TTL-based in-memory cache for DNS records
- `src/main.rs`: CLI interface

## Error Handling

The resolver properly handles:
- **NXDOMAIN (RCODE 3)**: Domain name does not exist
- **SERVFAIL (RCODE 2)**: Server failure
- **Timeout**: Network timeout when querying nameservers
- **Invalid packets**: Malformed DNS responses

## Example Output

```
$ cargo run -- google.com A
google.com 300 IN A 142.250.191.14
```

## Testing

You can test the resolver with various domains:

```bash
# Test A record
cargo run -- google.com A

# Test NS record
cargo run -- google.com NS

# Test MX record
cargo run -- gmail.com MX

# Test non-existent domain (should show NXDOMAIN error)
cargo run -- this-domain-does-not-exist-12345.com A
```

## Implementation Notes

- Uses standard DNS port 53 over UDP; TCP is used when the response is truncated (TC bit set)
- Implements DNS name compression (RFC 1035) for encoding and decoding
- Record classes IN, CH, and HS are supported; IN is used in practice
- Handles DNS response codes according to RFC 1035
- Cache automatically expires records based on TTL
- Follows CNAME chains (recursive follow when the answer is a CNAME)

