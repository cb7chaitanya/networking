pub mod cache;
pub mod dns;
pub mod network;
pub mod resolver;
pub mod server;

pub use cache::{CacheEntryInfo, DnsCache};
pub use dns::{DnsError, RecordType, ResourceRecord};
pub use network::{query, query_tcp, query_udp, ROOT_SERVERS};
pub use resolver::{DnsResolver, ResolverMetrics, GLOBAL_TIMEOUT, MAX_CNAME_DEPTH};
