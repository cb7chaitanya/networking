use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    /// Unknown type (e.g. from server response); allows decoding any qtype/rtype.
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            _ => RecordType::Unknown(value),
        })
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::Unknown(v) => v,
        }
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "NS" => Ok(RecordType::NS),
            "CNAME" => Ok(RecordType::CNAME),
            "SOA" => Ok(RecordType::SOA),
            "PTR" => Ok(RecordType::PTR),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "AAAA" => Ok(RecordType::AAAA),
            _ => Err(format!("Unknown record type: {}", s)),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN = 1,
    CH = 3, // Chaos (historic)
    HS = 4, // Hesiod (historic)
    /// Unknown class (e.g. from server response); allows decoding any qclass/class.
    Unknown(u16),
}

impl RecordClass {
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::Unknown(value),
        })
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    PTR(String),
    MX {
        priority: u16,
        exchange: String,
    },
    TXT(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub record_type: RecordType,
    pub class: RecordClass,
    pub ttl: u32,
    pub data: RecordData,
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordClass::IN => write!(f, "IN"),
            RecordClass::CH => write!(f, "CH"),
            RecordClass::HS => write!(f, "HS"),
            RecordClass::Unknown(v) => write!(f, "CLASS{}", v),
        }
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?} ",
            self.name, self.ttl, self.class, self.record_type
        )?;
        match &self.data {
            RecordData::A(a) => write!(f, "{a}"),
            RecordData::AAAA(a) => write!(f, "{a}"),
            RecordData::NS(n) => write!(f, "{n}"),
            RecordData::CNAME(c) => write!(f, "{c}"),
            RecordData::PTR(p) => write!(f, "{p}"),
            RecordData::MX { priority, exchange } => write!(f, "{} {}", priority, exchange),
            RecordData::TXT(t) => write!(f, "\"{t}\""),
            RecordData::SOA {
                mname,
                rname,
                serial,
                ..
            } => write!(f, "{} {} {}", mname, rname, serial),
            RecordData::Unknown(_) => write!(f, "<unknown>"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            flags: 0x0000, // ❗ RD = 0 → iterative resolver
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    pub fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0 // TC (Truncated) bit is bit 9
    }

    #[allow(dead_code)]
    pub fn is_authoritative(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DnsError> {
        if bytes.len() < 12 {
            return Err(DnsError::InvalidPacket("Header too short".into()));
        }

        Ok(Self {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.id.to_be_bytes(),
            self.flags.to_be_bytes(),
            self.qdcount.to_be_bytes(),
            self.ancount.to_be_bytes(),
            self.nscount.to_be_bytes(),
            self.arcount.to_be_bytes(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: RecordClass,
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl DnsPacket {
    pub fn new_query(id: u16, name: String, qtype: RecordType) -> Self {
        Self {
            header: DnsHeader::new_query(id),
            questions: vec![DnsQuestion {
                name,
                qtype,
                qclass: RecordClass::IN,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        // Ensure header counts match section lengths
        let mut header = self.header.clone();
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authorities.len() as u16;
        header.arcount = self.additionals.len() as u16;

        let mut out = header.to_bytes();
        let mut compression_map = HashMap::new();

        for q in &self.questions {
            encode_domain_name(&mut out, &q.name, &mut compression_map)?;
            out.extend_from_slice(&q.qtype.to_u16().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_u16().to_be_bytes());
        }

        for rr in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
        {
            encode_resource_record(&mut out, rr, &mut compression_map)?;
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, DnsError> {
        let header = DnsHeader::from_bytes(data)?;
        let mut offset = 12;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            let (name, o) = decode_domain_name(data, offset)?;
            offset = o;
            let q_fixed = data
                .get(offset..offset + 4)
                .ok_or_else(|| DnsError::InvalidPacket("question overflow".into()))?;
            let qtype = u16::from_be_bytes([q_fixed[0], q_fixed[1]]);
            let qclass = u16::from_be_bytes([q_fixed[2], q_fixed[3]]);
            offset += 4;

            questions.push(DnsQuestion {
                name,
                qtype: RecordType::from_u16(qtype)
                    .ok_or(DnsError::InvalidPacket("bad qtype".into()))?,
                qclass: RecordClass::from_u16(qclass)
                    .ok_or(DnsError::InvalidPacket("bad qclass".into()))?,
            });
        }

        // Extract counts before moving header into struct
        let ancount = header.ancount;
        let nscount = header.nscount;
        let arcount = header.arcount;

        let mut decode_rrs = |count| {
            let mut v = Vec::new();
            for _ in 0..count {
                let (rr, o) = decode_resource_record(data, offset)?;
                offset = o;
                v.push(rr);
            }
            Ok::<_, DnsError>(v)
        };

        Ok(Self {
            header,
            questions,
            answers: decode_rrs(ancount)?,
            authorities: decode_rrs(nscount)?,
            additionals: decode_rrs(arcount)?,
        })
    }
}

/* ============================
Domain + RDATA decoding
============================ */

fn encode_domain_name(
    out: &mut Vec<u8>,
    name: &str,
    compression_map: &mut HashMap<String, usize>,
) -> Result<(), DnsError> {
    // DNS root: single zero byte (RFC 1035)
    if name.is_empty() || name == "." {
        out.push(0);
        return Ok(());
    }
    // Check if we've already encoded this exact name
    if let Some(&offset) = compression_map.get(name) {
        // Use compression pointer (must be < 16384)
        if offset < 16384 {
            let ptr = 0xC000u16 | (offset as u16);
            out.extend_from_slice(&ptr.to_be_bytes());
            return Ok(());
        }
    }

    // Check for suffix compression (e.g., if "example.com" is already encoded,
    // we can compress "www.example.com")
    let parts: Vec<&str> = name.split('.').collect();
    for i in 1..parts.len() {
        let suffix = parts[i..].join(".");
        if let Some(&offset) = compression_map.get(&suffix) {
            // Encode the prefix labels, then use compression pointer
            let prefix_start = out.len();
            for label in parts.iter().take(i) {
                if label.len() > 63 {
                    return Err(DnsError::InvalidPacket("label too long".into()));
                }
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            // Use compression pointer for the suffix
            if offset < 16384 {
                let ptr = 0xC000u16 | (offset as u16);
                out.extend_from_slice(&ptr.to_be_bytes());

                // Record the full name and its prefixes for future compression
                for k in 0..=i {
                    let partial = parts[k..].join(".");
                    if !partial.is_empty() {
                        compression_map.entry(partial).or_insert(if k == i {
                            offset
                        } else {
                            prefix_start
                        });
                    }
                }
                return Ok(());
            }
        }
    }

    // No compression possible, encode normally
    let start_offset = out.len();
    let parts: Vec<&str> = name.split('.').collect();
    let mut current_offset = start_offset;

    for (i, label) in parts.iter().enumerate() {
        if label.len() > 63 {
            return Err(DnsError::InvalidPacket("label too long".into()));
        }

        // Record this suffix before encoding (for compression)
        let suffix = parts[i..].join(".");
        if !suffix.is_empty() {
            compression_map.entry(suffix).or_insert(current_offset);
        }

        // Encode the label
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
        current_offset += 1 + label.len(); // length byte + label bytes
    }
    out.push(0);

    Ok(())
}

fn encode_resource_record(
    out: &mut Vec<u8>,
    rr: &ResourceRecord,
    compression_map: &mut HashMap<String, usize>,
) -> Result<(), DnsError> {
    encode_domain_name(out, &rr.name, compression_map)?;
    out.extend_from_slice(&rr.record_type.to_u16().to_be_bytes());
    out.extend_from_slice(&rr.class.to_u16().to_be_bytes());
    out.extend_from_slice(&rr.ttl.to_be_bytes());
    let rdlen_pos = out.len();
    out.extend_from_slice(&[0u8, 0u8]); // rdlength placeholder
    encode_record_data(out, rr, compression_map)?;
    let rdlen = out.len() - rdlen_pos - 2;
    out[rdlen_pos] = (rdlen >> 8) as u8;
    out[rdlen_pos + 1] = rdlen as u8;
    Ok(())
}

fn encode_record_data(
    out: &mut Vec<u8>,
    rr: &ResourceRecord,
    compression_map: &mut HashMap<String, usize>,
) -> Result<(), DnsError> {
    match &rr.data {
        RecordData::A(addr) => {
            out.extend_from_slice(&addr.octets());
        }
        RecordData::AAAA(addr) => {
            out.extend_from_slice(&addr.octets());
        }
        RecordData::NS(name) | RecordData::CNAME(name) | RecordData::PTR(name) => {
            encode_domain_name(out, name, compression_map)?;
        }
        RecordData::MX { priority, exchange } => {
            out.extend_from_slice(&priority.to_be_bytes());
            encode_domain_name(out, exchange, compression_map)?;
        }
        RecordData::TXT(s) => {
            // RFC 1035: one or more length-prefixed character strings (max 255 per chunk)
            let bytes = s.as_bytes();
            let mut pos = 0;
            while pos < bytes.len() {
                let chunk_len = (bytes.len() - pos).min(255);
                out.push(chunk_len as u8);
                out.extend_from_slice(&bytes[pos..pos + chunk_len]);
                pos += chunk_len;
            }
        }
        RecordData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            encode_domain_name(out, mname, compression_map)?;
            encode_domain_name(out, rname, compression_map)?;
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        RecordData::Unknown(rdata) => {
            out.extend_from_slice(rdata);
        }
    }
    Ok(())
}

fn decode_domain_name(data: &[u8], offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut next_offset = None;
    let mut jumps = 0usize;

    loop {
        let len = *data
            .get(cursor)
            .ok_or_else(|| DnsError::InvalidPacket("name overflow".into()))?;

        if len == 0 {
            let consumed = next_offset.unwrap_or(cursor + 1);
            return Ok((labels.join("."), consumed));
        }

        if len & 0xC0 == 0xC0 {
            let b2 = *data
                .get(cursor + 1)
                .ok_or_else(|| DnsError::InvalidPacket("ptr overflow".into()))?
                as usize;
            let ptr = (((len & 0x3F) as usize) << 8) | b2;
            if ptr >= data.len() {
                return Err(DnsError::InvalidPacket("ptr out of bounds".into()));
            }
            if next_offset.is_none() {
                next_offset = Some(cursor + 2);
            }
            cursor = ptr;
            jumps += 1;
            if jumps > data.len() {
                return Err(DnsError::InvalidPacket("compression loop".into()));
            }
            continue;
        }

        if len & 0xC0 != 0 {
            return Err(DnsError::InvalidPacket("bad label length".into()));
        }

        let label_len = len as usize;
        let start = cursor + 1;
        let end = start
            .checked_add(label_len)
            .ok_or_else(|| DnsError::InvalidPacket("label overflow".into()))?;
        let bytes = data
            .get(start..end)
            .ok_or_else(|| DnsError::InvalidPacket("label overflow".into()))?;
        let label =
            std::str::from_utf8(bytes).map_err(|_| DnsError::InvalidPacket("utf8".into()))?;
        labels.push(label.to_string());
        cursor = end;
    }
}

fn decode_resource_record(data: &[u8], offset: usize) -> Result<(ResourceRecord, usize), DnsError> {
    let (name, mut offset) = decode_domain_name(data, offset)?;
    let rr_fixed = data
        .get(offset..offset + 10)
        .ok_or_else(|| DnsError::InvalidPacket("rr header overflow".into()))?;
    let rtype = u16::from_be_bytes([rr_fixed[0], rr_fixed[1]]);
    let class = u16::from_be_bytes([rr_fixed[2], rr_fixed[3]]);
    let ttl = u32::from_be_bytes([rr_fixed[4], rr_fixed[5], rr_fixed[6], rr_fixed[7]]);
    let rdlen = u16::from_be_bytes([rr_fixed[8], rr_fixed[9]]) as usize;
    offset += 10;

    let end = offset
        .checked_add(rdlen)
        .ok_or_else(|| DnsError::InvalidPacket("rdata overflow".into()))?;
    let rdata = data
        .get(offset..end)
        .ok_or_else(|| DnsError::InvalidPacket("rdata overflow".into()))?;
    let parsed = decode_record_data(rtype, data, offset, rdata)?;
    offset = end;

    Ok((
        ResourceRecord {
            name,
            record_type: RecordType::from_u16(rtype)
                .ok_or(DnsError::InvalidPacket("rtype".into()))?,
            class: RecordClass::from_u16(class).ok_or(DnsError::InvalidPacket("class".into()))?,
            ttl,
            data: parsed,
        },
        offset,
    ))
}

fn decode_record_data(
    rtype: u16,
    packet: &[u8],
    offset: usize,
    rdata: &[u8],
) -> Result<RecordData, DnsError> {
    Ok(match rtype {
        1 => {
            if rdata.len() != 4 {
                return Err(DnsError::InvalidPacket("bad A rdata len".into()));
            }
            RecordData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
        }
        28 => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| DnsError::InvalidPacket("bad AAAA rdata len".into()))?;
            RecordData::AAAA(Ipv6Addr::from(bytes))
        }
        2 => {
            let (ns, end) = decode_domain_name(packet, offset)?;
            if end > offset + rdata.len() {
                return Err(DnsError::InvalidPacket("bad NS rdata len".into()));
            }
            RecordData::NS(ns)
        }
        5 => {
            let (cname, end) = decode_domain_name(packet, offset)?;
            if end > offset + rdata.len() {
                return Err(DnsError::InvalidPacket("bad CNAME rdata len".into()));
            }
            RecordData::CNAME(cname)
        }
        12 => {
            let (ptr, end) = decode_domain_name(packet, offset)?;
            if end > offset + rdata.len() {
                return Err(DnsError::InvalidPacket("bad PTR rdata len".into()));
            }
            RecordData::PTR(ptr)
        }
        15 => {
            if rdata.len() < 3 {
                return Err(DnsError::InvalidPacket("bad MX rdata len".into()));
            }
            let prio = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (ex, end) = decode_domain_name(packet, offset + 2)?;
            if end > offset + rdata.len() {
                return Err(DnsError::InvalidPacket("bad MX rdata len".into()));
            }
            RecordData::MX {
                priority: prio,
                exchange: ex,
            }
        }
        6 => {
            let rdata_end = offset
                .checked_add(rdata.len())
                .ok_or_else(|| DnsError::InvalidPacket("bad SOA rdata len".into()))?;
            let (m, o1) = decode_domain_name(packet, offset)?;
            let (r, o2) = decode_domain_name(packet, o1)?;
            let nums_end = o2
                .checked_add(20)
                .ok_or_else(|| DnsError::InvalidPacket("bad SOA rdata len".into()))?;
            if nums_end > rdata_end {
                return Err(DnsError::InvalidPacket("bad SOA rdata len".into()));
            }
            let nums = packet
                .get(o2..nums_end)
                .ok_or_else(|| DnsError::InvalidPacket("bad SOA rdata len".into()))?;
            RecordData::SOA {
                mname: m,
                rname: r,
                serial: u32::from_be_bytes([nums[0], nums[1], nums[2], nums[3]]),
                refresh: u32::from_be_bytes([nums[4], nums[5], nums[6], nums[7]]),
                retry: u32::from_be_bytes([nums[8], nums[9], nums[10], nums[11]]),
                expire: u32::from_be_bytes([nums[12], nums[13], nums[14], nums[15]]),
                minimum: u32::from_be_bytes([nums[16], nums[17], nums[18], nums[19]]),
            }
        }
        16 => {
            // TXT records: one or more length-prefixed character strings
            let mut txt_parts = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let len = rdata[pos] as usize;
                pos += 1;
                if pos + len <= rdata.len() {
                    let txt_bytes = &rdata[pos..pos + len];
                    txt_parts.push(String::from_utf8_lossy(txt_bytes).to_string());
                    pos += len;
                } else {
                    // Invalid length, break to avoid panic
                    break;
                }
            }
            RecordData::TXT(txt_parts.join(""))
        }
        _ => RecordData::Unknown(rdata.to_vec()),
    })
}

#[derive(Error, Debug, Clone)]
pub enum DnsError {
    #[error("Invalid DNS packet: {0}")]
    InvalidPacket(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("NXDOMAIN")]
    NxDomain,
    #[error("SERVFAIL")]
    ServFail,
    #[error("Timeout")]
    Timeout,
}

impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::TimedOut {
            DnsError::Timeout
        } else {
            DnsError::Network(err.to_string())
        }
    }
}

impl From<std::net::AddrParseError> for DnsError {
    fn from(err: std::net::AddrParseError) -> Self {
        DnsError::Network(format!("Invalid address: {}", err))
    }
}
