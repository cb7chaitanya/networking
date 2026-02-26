pub mod cache;
pub mod dns;
pub mod network;
pub mod resolver;

pub use dns::{DnsError, RecordType, ResourceRecord};
pub use network::{query, query_tcp, query_udp, ROOT_SERVERS};
pub use resolver::DnsResolver;
