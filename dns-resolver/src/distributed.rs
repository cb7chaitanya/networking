use std::time::Duration;

use gossip_membership::app_state::{
    AppStateHandle, DnsCacheEntry, DnsCacheValue, DnsRecordData as GossipRecordData,
    DnsResourceRecord as GossipResourceRecord,
};

use crate::dns::{DnsError, RecordClass, RecordData, RecordType, ResourceRecord};

pub enum DistributedCacheHit {
    Positive(Vec<ResourceRecord>),
    Negative { ttl: u32 },
}

pub fn lookup(
    handle: &AppStateHandle,
    name: &str,
    record_type: RecordType,
) -> Result<Option<DistributedCacheHit>, DnsError> {
    let Some(entry) = handle.dns_entry(name, record_type.to_u16()) else {
        return Ok(None);
    };

    let ttl = remaining_ttl(entry.expires_at_unix_ms)?;
    if ttl == 0 {
        return Ok(None);
    }

    let hit = match entry.value {
        DnsCacheValue::Positive { records } => {
            let records = records
                .into_iter()
                .map(|record| Ok(ResourceRecord {
                    name: entry.name.clone(),
                    record_type,
                    class: RecordClass::from_u16(record.class)
                        .ok_or_else(|| DnsError::InvalidPacket("invalid class".into()))?,
                    ttl,
                    data: from_gossip_data(record.data)?,
                }))
                .collect::<Result<Vec<_>, DnsError>>()?;
            DistributedCacheHit::Positive(records)
        }
        DnsCacheValue::Negative => DistributedCacheHit::Negative { ttl },
    };

    Ok(Some(hit))
}

pub fn publish_positive(handle: &AppStateHandle, records: &[ResourceRecord]) {
    if records.is_empty() {
        return;
    }

    let ttl = records.iter().map(|record| record.ttl).min().unwrap_or(0);
    if ttl == 0 {
        return;
    }

    let entry = DnsCacheEntry::positive(
        records[0].name.clone(),
        records[0].record_type.to_u16(),
        Duration::from_secs(ttl as u64),
        records.iter().map(to_gossip_record).collect(),
    );
    handle.publish_dns_entry(entry);
}

pub fn publish_negative(
    handle: &AppStateHandle,
    name: &str,
    record_type: RecordType,
    ttl: u32,
) {
    if ttl == 0 {
        return;
    }

    handle.publish_dns_entry(DnsCacheEntry::negative(
        name.to_string(),
        record_type.to_u16(),
        Duration::from_secs(ttl as u64),
    ));
}

fn remaining_ttl(expires_at_unix_ms: u64) -> Result<u32, DnsError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DnsError::ServFail)?
        .as_millis() as u64;
    if expires_at_unix_ms <= now {
        return Ok(0);
    }

    let remaining_ms = expires_at_unix_ms - now;
    Ok(remaining_ms.div_ceil(1_000).min(u32::MAX as u64) as u32)
}

fn to_gossip_record(record: &ResourceRecord) -> GossipResourceRecord {
    GossipResourceRecord {
        class: record.class.to_u16(),
        ttl: record.ttl,
        data: to_gossip_data(&record.data),
    }
}

fn to_gossip_data(data: &RecordData) -> GossipRecordData {
    match data {
        RecordData::A(addr) => GossipRecordData::A(*addr),
        RecordData::AAAA(addr) => GossipRecordData::AAAA(*addr),
        RecordData::NS(value) => GossipRecordData::NS(value.clone()),
        RecordData::CNAME(value) => GossipRecordData::CNAME(value.clone()),
        RecordData::PTR(value) => GossipRecordData::PTR(value.clone()),
        RecordData::MX { priority, exchange } => GossipRecordData::MX {
            priority: *priority,
            exchange: exchange.clone(),
        },
        RecordData::TXT(value) => GossipRecordData::TXT(value.clone()),
        RecordData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => GossipRecordData::SOA {
            mname: mname.clone(),
            rname: rname.clone(),
            serial: *serial,
            refresh: *refresh,
            retry: *retry,
            expire: *expire,
            minimum: *minimum,
        },
        RecordData::Unknown(bytes) => GossipRecordData::Unknown(bytes.clone()),
    }
}

fn from_gossip_data(data: GossipRecordData) -> Result<RecordData, DnsError> {
    Ok(match data {
        GossipRecordData::A(addr) => RecordData::A(addr),
        GossipRecordData::AAAA(addr) => RecordData::AAAA(addr),
        GossipRecordData::NS(value) => RecordData::NS(value),
        GossipRecordData::CNAME(value) => RecordData::CNAME(value),
        GossipRecordData::PTR(value) => RecordData::PTR(value),
        GossipRecordData::MX { priority, exchange } => RecordData::MX { priority, exchange },
        GossipRecordData::TXT(value) => RecordData::TXT(value),
        GossipRecordData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => RecordData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        },
        GossipRecordData::Unknown(bytes) => RecordData::Unknown(bytes),
    })
}
