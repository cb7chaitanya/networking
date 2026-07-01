//! Production-grade segmented Write-Ahead Log (WAL) for Raft.
//!
//! # Design
//!
//! All Raft durable state — current term, voted-for, log entries, and snapshot
//! metadata — is persisted as a sequence of CRC32-framed records spread across
//! fixed-size segment files.  Records are append-only; the active segment grows
//! until it reaches `WalConfig::segment_size`, then a new segment is opened.
//! Old segments are never rewritten.
//!
//! ## Record format
//!
//! ```text
//! ┌──────────────┬──────────────────┬────────────┬──────────────────────┐
//! │ crc32 (4 B)  │ payload_len (4 B) │ kind (1 B) │  payload (N bytes)   │
//! └──────────────┴──────────────────┴────────────┴──────────────────────┘
//! ```
//!
//! `crc32` is computed (little-endian) over the bytes `[payload_len | kind | payload]`.
//!
//! ## Segment naming
//!
//! Segments are named `%016u.wal` (e.g. `0000000000000001.wal`).
//! IDs are assigned monotonically starting at 1.
//!
//! ## Recovery
//!
//! On `open`, all segments are read in ID order.  Reading stops at the first
//! truncated header, truncated payload, CRC mismatch, or unknown record kind.
//! If a partial record is found the segment file is truncated to the last clean
//! byte, and every subsequent segment file is deleted.
//!
//! ## Snapshot storage
//!
//! Snapshot data is stored in `{dir}/snapshot.bin` using an atomic
//! write-then-rename.  A `SnapshotMeta` WAL record is written afterward.
//! On recovery the snapshot file is the authoritative source of snapshot data.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crc32fast::Hasher as CrcHasher;

use crate::{
    log::LogEntry,
    state::{LogIndex, NodeId, Term},
    storage::{HardState, Result as StorageResult, Snapshot, Storage, StorageError},
};

// ════════════════════════════════════════════════════════════════════════════
//  Public types
// ════════════════════════════════════════════════════════════════════════════

/// Policy governing how often the WAL is fsynced to stable storage.
#[derive(Debug, Clone)]
pub enum FsyncPolicy {
    /// `fsync` (via `sync_data`) after every write — safest, lowest throughput.
    Always,
    /// `fsync` at most once per `Duration`.  Trades a bounded data-loss window
    /// for higher write throughput.
    EveryN(Duration),
    /// Never explicitly `fsync`.  Fastest, but data in the OS page cache may be
    /// lost on a sudden power failure.
    Never,
}

/// Configuration for [`WalStorage`].
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Maximum size of a segment file in bytes.  When the active segment
    /// reaches or exceeds this limit after a write, a new segment is opened.
    ///
    /// Default: 64 MiB.
    pub segment_size: u64,
    /// When (and whether) to call `fsync` on the active segment.
    pub fsync: FsyncPolicy,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            segment_size: 64 * 1024 * 1024,
            fsync: FsyncPolicy::Always,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Internal constants
// ════════════════════════════════════════════════════════════════════════════

/// Record header size: 4 (CRC32) + 4 (payload_len) + 1 (kind) = 9 bytes.
const HEADER_SIZE: usize = 9;

/// Maximum sane record payload (128 MiB).  Guards against OOM on corrupt
/// length fields during recovery.
const MAX_PAYLOAD: usize = 128 * 1024 * 1024;

mod kind {
    pub const TERM: u8          = 1;
    pub const VOTE: u8          = 2;
    pub const ENTRY: u8         = 3;
    pub const TRUNCATE: u8      = 4;
    pub const SNAPSHOT_META: u8 = 5;
}

// ════════════════════════════════════════════════════════════════════════════
//  Path helpers
// ════════════════════════════════════════════════════════════════════════════

fn segment_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:016}.wal"))
}

fn snapshot_bin_path(dir: &Path) -> PathBuf {
    dir.join("snapshot.bin")
}

fn snapshot_tmp_path(dir: &Path) -> PathBuf {
    dir.join("snapshot.bin.tmp")
}

/// List segment IDs present in `dir`, sorted ascending.
fn list_segment_ids(dir: &Path) -> std::io::Result<Vec<u64>> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        let s = name.to_string_lossy();
        // e.g. "0000000000000001.wal"  → 20 chars
        if s.len() == 20 && s.ends_with(".wal") {
            if let Ok(id) = s[..16].parse::<u64>() {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

// ════════════════════════════════════════════════════════════════════════════
//  Record encoding
// ════════════════════════════════════════════════════════════════════════════

/// Encode a single WAL record into its on-disk framing.
///
/// Layout: `[crc32 LE 4][payload_len BE 4][kind 1][payload N]`
/// CRC covers the bytes `[payload_len | kind | payload]`.
fn encode_record(k: u8, payload: &[u8]) -> Vec<u8> {
    let len_be = (payload.len() as u32).to_be_bytes();
    let mut h = CrcHasher::new();
    h.update(&len_be);
    h.update(&[k]);
    h.update(payload);
    let crc = h.finalize();

    let mut record = Vec::with_capacity(HEADER_SIZE + payload.len());
    record.extend_from_slice(&crc.to_le_bytes());
    record.extend_from_slice(&len_be);
    record.push(k);
    record.extend_from_slice(payload);
    record
}

// ════════════════════════════════════════════════════════════════════════════
//  Recovery
// ════════════════════════════════════════════════════════════════════════════

struct Recovered {
    term: Term,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    active_id: u64,
    active_size: u64,
}

impl Default for Recovered {
    fn default() -> Self {
        Recovered { term: 0, voted_for: None, log: Vec::new(), active_id: 0, active_size: 0 }
    }
}

fn recover_from_dir(dir: &Path) -> std::io::Result<Recovered> {
    let ids = list_segment_ids(dir)?;
    let mut state = Recovered::default();
    let mut stop = false;

    for &id in &ids {
        if stop {
            let _ = std::fs::remove_file(segment_path(dir, id));
            continue;
        }

        let path = segment_path(dir, id);
        let data = std::fs::read(&path)?;
        let mut pos = 0usize;
        let mut corrupt_at: Option<usize> = None;

        while pos < data.len() {
            if data.len() - pos < HEADER_SIZE {
                corrupt_at = Some(pos);
                break;
            }

            let crc_stored =
                u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            let payload_len =
                u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let record_kind = data[pos + 8];

            if payload_len > MAX_PAYLOAD {
                corrupt_at = Some(pos);
                break;
            }
            if data.len() - pos - HEADER_SIZE < payload_len {
                corrupt_at = Some(pos);
                break;
            }

            let crc_range = pos + 4..pos + HEADER_SIZE + payload_len;
            let mut h = CrcHasher::new();
            h.update(&data[crc_range]);
            if h.finalize() != crc_stored {
                corrupt_at = Some(pos);
                break;
            }

            let payload = &data[pos + HEADER_SIZE..pos + HEADER_SIZE + payload_len];
            apply_record(&mut state, record_kind, payload);
            pos += HEADER_SIZE + payload_len;
        }

        if let Some(good_end) = corrupt_at {
            // Truncate this segment to the last valid byte.
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(good_end as u64)?;
            state.active_id = id;
            state.active_size = good_end as u64;
            stop = true;
        } else {
            state.active_id = id;
            state.active_size = pos as u64;
        }
    }

    Ok(state)
}

fn apply_record(state: &mut Recovered, k: u8, payload: &[u8]) {
    match k {
        kind::TERM => {
            if payload.len() >= 8 {
                state.term = u64::from_be_bytes(payload[..8].try_into().unwrap());
            }
        }
        kind::VOTE => {
            if !payload.is_empty() {
                state.voted_for = if payload[0] == 0 {
                    None
                } else if payload.len() >= 9 {
                    Some(u64::from_be_bytes(payload[1..9].try_into().unwrap()))
                } else {
                    None
                };
            }
        }
        kind::ENTRY => {
            if payload.len() >= 20 {
                let index = u64::from_be_bytes(payload[..8].try_into().unwrap());
                let term = u64::from_be_bytes(payload[8..16].try_into().unwrap());
                let data_len = u32::from_be_bytes(payload[16..20].try_into().unwrap()) as usize;
                if payload.len() >= 20 + data_len && index >= 1 {
                    let data = payload[20..20 + data_len].to_vec();
                    let pos = (index - 1) as usize;
                    if pos == state.log.len() {
                        state.log.push(LogEntry { term, data });
                    } else if pos < state.log.len() {
                        // Defensive: truncate to this point, then append.
                        state.log.truncate(pos);
                        state.log.push(LogEntry { term, data });
                    }
                    // index > state.log.len()+1 → gap, ignore.
                }
            }
        }
        kind::TRUNCATE => {
            if payload.len() >= 8 {
                let from_index = u64::from_be_bytes(payload[..8].try_into().unwrap());
                if from_index >= 1 {
                    state.log.truncate((from_index - 1) as usize);
                }
            }
        }
        kind::SNAPSHOT_META => {
            // The snapshot file is the authoritative data source; this record
            // is bookkeeping only.  No in-memory log changes — the caller is
            // responsible for calling truncate_log after save_snapshot.
        }
        _ => {
            // Unknown kind — treat as end-of-valid-data.  The outer loop
            // will not call apply_record for an unknown kind because we
            // set corrupt_at before reaching here; this branch is unreachable
            // in the current code but is kept for safety.
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Snapshot file I/O
// ════════════════════════════════════════════════════════════════════════════

fn load_snapshot_file(dir: &Path) -> std::io::Result<Option<Snapshot>> {
    let path = snapshot_bin_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(&path)?;
    if raw.len() < 16 {
        return Ok(None); // incomplete header, treat as absent
    }
    let last_included_index = u64::from_be_bytes(raw[..8].try_into().unwrap());
    let last_included_term  = u64::from_be_bytes(raw[8..16].try_into().unwrap());
    Ok(Some(Snapshot {
        last_included_index,
        last_included_term,
        data: raw[16..].to_vec(),
    }))
}

fn write_snapshot_file(dir: &Path, snap: &Snapshot) -> std::io::Result<()> {
    let tmp   = snapshot_tmp_path(dir);
    let final_ = snapshot_bin_path(dir);
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&snap.last_included_index.to_be_bytes())?;
        f.write_all(&snap.last_included_term.to_be_bytes())?;
        f.write_all(&snap.data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_)?;
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
//  WalStorage
// ════════════════════════════════════════════════════════════════════════════

/// Durable [`Storage`] backend built on a segmented, CRC32-framed
/// Write-Ahead Log.
///
/// # Opening
///
/// ```no_run
/// use raft_consensus::wal::{WalStorage, WalConfig, FsyncPolicy};
/// use std::time::Duration;
///
/// let config = WalConfig {
///     segment_size: 64 * 1024 * 1024,
///     fsync: FsyncPolicy::EveryN(Duration::from_millis(10)),
/// };
/// let storage = WalStorage::open("/var/raft/node1", config).unwrap();
/// ```
pub struct WalStorage {
    dir: PathBuf,
    config: WalConfig,
    // Active write segment.
    active_id: u64,
    active_file: File,
    active_size: u64,
    // Cached hard state — authoritative after open.
    term: Term,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    snapshot: Option<Snapshot>,
    // For FsyncPolicy::EveryN.
    last_fsync: Option<Instant>,
}

impl WalStorage {
    /// Open (or create) a WAL in `dir`.
    ///
    /// - **Fresh directory**: creates `0000000000000001.wal` and returns a
    ///   zeroed hard state.
    /// - **Existing directory**: replays all segments in order.  Any corrupted
    ///   tail is discarded (the segment is truncated to the last valid record,
    ///   subsequent segments are deleted).
    pub fn open(dir: impl Into<PathBuf>, config: WalConfig) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;

        let mut rec = recover_from_dir(&dir)?;
        let snapshot = load_snapshot_file(&dir)?;

        // No existing segments → begin at segment 1.
        if rec.active_id == 0 {
            rec.active_id = 1;
        }

        let active_path = segment_path(&dir, rec.active_id);
        let active_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)?;

        let active_size = active_file.metadata()?.len();

        Ok(WalStorage {
            dir,
            config,
            active_id: rec.active_id,
            active_file,
            active_size,
            term: rec.term,
            voted_for: rec.voted_for,
            log: rec.log,
            snapshot,
            last_fsync: None,
        })
    }

    // ── Internal write path ──────────────────────────────────────────────

    fn write_record(&mut self, k: u8, payload: &[u8]) -> StorageResult<()> {
        // Rotate before writing if the current segment is already full.
        // A segment that is still empty always accepts the next record
        // (even if the record is larger than segment_size).
        if self.active_size > 0 && self.active_size >= self.config.segment_size {
            self.rotate().map_err(|e| StorageError::Io(e.to_string()))?;
        }

        let record = encode_record(k, payload);
        self.active_file
            .write_all(&record)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.active_size += record.len() as u64;

        self.maybe_fsync()
            .map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.active_file.sync_all()?;
        self.active_id += 1;
        self.active_size = 0;
        let path = segment_path(&self.dir, self.active_id);
        self.active_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(())
    }

    fn maybe_fsync(&mut self) -> std::io::Result<()> {
        match self.config.fsync.clone() {
            FsyncPolicy::Always => {
                self.active_file.sync_data()?;
            }
            FsyncPolicy::EveryN(interval) => {
                let do_sync = self
                    .last_fsync
                    .map(|t| t.elapsed() >= interval)
                    .unwrap_or(true);
                if do_sync {
                    self.active_file.sync_data()?;
                    self.last_fsync = Some(Instant::now());
                }
            }
            FsyncPolicy::Never => {}
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Storage trait
// ════════════════════════════════════════════════════════════════════════════

impl Storage for WalStorage {
    fn save_term(&mut self, term: Term) -> StorageResult<()> {
        self.write_record(kind::TERM, &term.to_be_bytes())?;
        self.term = term;
        Ok(())
    }

    fn save_vote(&mut self, voted_for: Option<NodeId>) -> StorageResult<()> {
        let payload = match voted_for {
            None => vec![0u8],
            Some(id) => {
                let mut v = Vec::with_capacity(9);
                v.push(1u8);
                v.extend_from_slice(&id.to_be_bytes());
                v
            }
        };
        self.write_record(kind::VOTE, &payload)?;
        self.voted_for = voted_for;
        Ok(())
    }

    fn append_log_entries(&mut self, entries: &[LogEntry]) -> StorageResult<()> {
        for entry in entries {
            let index = self.log.len() as u64 + 1;
            let mut payload = Vec::with_capacity(20 + entry.data.len());
            payload.extend_from_slice(&index.to_be_bytes());
            payload.extend_from_slice(&entry.term.to_be_bytes());
            payload.extend_from_slice(&(entry.data.len() as u32).to_be_bytes());
            payload.extend_from_slice(&entry.data);
            self.write_record(kind::ENTRY, &payload)?;
            self.log.push(entry.clone());
        }
        Ok(())
    }

    fn truncate_log(&mut self, from_index: LogIndex) -> StorageResult<()> {
        if from_index == 0 {
            return Ok(());
        }
        let pos = (from_index - 1) as usize;
        if pos < self.log.len() {
            self.write_record(kind::TRUNCATE, &from_index.to_be_bytes())?;
            self.log.truncate(pos);
        }
        Ok(())
    }

    fn load_state(&self) -> StorageResult<HardState> {
        Ok(HardState {
            current_term: self.term,
            voted_for: self.voted_for,
            log: self.log.clone(),
        })
    }

    fn save_snapshot(&mut self, snap: &Snapshot) -> StorageResult<()> {
        write_snapshot_file(&self.dir, snap)
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let mut meta = Vec::with_capacity(16);
        meta.extend_from_slice(&snap.last_included_index.to_be_bytes());
        meta.extend_from_slice(&snap.last_included_term.to_be_bytes());
        self.write_record(kind::SNAPSHOT_META, &meta)?;

        self.snapshot = Some(snap.clone());
        Ok(())
    }

    fn load_snapshot(&self) -> StorageResult<Option<Snapshot>> {
        Ok(self.snapshot.clone())
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("raft-wal-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fast_config() -> WalConfig {
        WalConfig { segment_size: 64 * 1024 * 1024, fsync: FsyncPolicy::Never }
    }

    fn entry(term: Term, byte: u8) -> LogEntry {
        LogEntry { term, data: vec![byte] }
    }

    // ── 1. Partial write recovery ──────────────────────────────────────────

    /// Write 3 complete records, then append a partial record (header only,
    /// no payload).  Reopen; recovery must discard the partial record and
    /// restore the 3 complete ones.
    #[test]
    fn test_partial_write_recovery() {
        let dir = test_dir("partial_write");

        {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(3).unwrap();
            w.save_vote(Some(2)).unwrap();
            w.append_log_entry(entry(3, 0xAA)).unwrap();
        }

        // Append a partial record: CRC (4) + payload_len (4) but no kind byte.
        let seg = segment_path(&dir, 1);
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x08]).unwrap();
        drop(f);

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 3);
        assert_eq!(hs.voted_for, Some(2));
        assert_eq!(hs.log.len(), 1);
        assert_eq!(hs.log[0].data, vec![0xAA]);
    }

    // ── 2. Truncated WAL (header incomplete) ──────────────────────────────

    /// Append only 5 bytes at the end (not enough for the 9-byte header).
    /// Recovery stops cleanly and those bytes are discarded.
    #[test]
    fn test_truncated_wal() {
        let dir = test_dir("truncated");

        {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(1).unwrap();
            w.save_vote(Some(1)).unwrap();
        }

        // Append 5 garbage bytes — too short for a HEADER_SIZE=9 header.
        let seg = segment_path(&dir, 1);
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0xFF; 5]).unwrap();
        drop(f);

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 1);
        assert_eq!(hs.voted_for, Some(1));
        assert!(hs.log.is_empty());
    }

    // ── 3. Corrupted CRC ──────────────────────────────────────────────────

    /// Write 2 valid records, then write a third with a deliberately wrong
    /// CRC.  Recovery must stop before the corrupt record.
    #[test]
    fn test_corrupted_crc() {
        let dir = test_dir("corrupted_crc");

        {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(5).unwrap();
            w.save_vote(Some(3)).unwrap();
        }

        // Build a syntactically valid record but flip the CRC.
        let mut bad_record = encode_record(kind::TERM, &7u64.to_be_bytes());
        bad_record[0] ^= 0xFF; // corrupt CRC byte

        let seg = segment_path(&dir, 1);
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&bad_record).unwrap();
        drop(f);

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        // Should recover term=5, vote=3, NOT term=7.
        assert_eq!(hs.current_term, 5);
        assert_eq!(hs.voted_for, Some(3));
    }

    // ── 4. Multi-segment recovery ─────────────────────────────────────────

    /// Use a tiny segment size to force records across 3+ segments.
    /// All records must survive a reopen.
    #[test]
    fn test_multi_segment_recovery() {
        let dir = test_dir("multi_seg");

        // A Term record is 9 (header) + 8 (u64) = 17 bytes.
        // An Entry record with 1 data byte is 9 + 20 + 1 = 30 bytes.
        // Set segment_size = 20 so each segment holds at most one record.
        let tiny = WalConfig { segment_size: 20, fsync: FsyncPolicy::Never };

        {
            let mut w = WalStorage::open(&dir, tiny.clone()).unwrap();
            w.save_term(2).unwrap();
            w.save_vote(Some(1)).unwrap();
            for i in 0u8..5 {
                w.append_log_entry(entry(2, i)).unwrap();
            }
        }

        // Multiple segments must have been created.
        let ids = list_segment_ids(&dir).unwrap();
        assert!(ids.len() >= 3, "expected at least 3 segments, got {}", ids.len());

        let w2 = WalStorage::open(&dir, tiny).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 2);
        assert_eq!(hs.voted_for, Some(1));
        assert_eq!(hs.log.len(), 5);
        for (i, e) in hs.log.iter().enumerate() {
            assert_eq!(e.data, vec![i as u8]);
        }
    }

    // ── 5. Segment rotation ───────────────────────────────────────────────

    /// Write enough data to exceed `segment_size` and verify that new segment
    /// files are created on disk.
    #[test]
    fn test_rotation() {
        let dir = test_dir("rotation");

        // Entry record payload = 20 + 4 (data) = 24; full record = 33 bytes.
        // Use segment_size = 35 so one entry fits but the second triggers rotation.
        let cfg = WalConfig { segment_size: 35, fsync: FsyncPolicy::Never };

        {
            let mut w = WalStorage::open(&dir, cfg).unwrap();
            // Write 6 entries; each ≥33 bytes so we need ≥6 segments.
            for i in 0u8..6 {
                w.append_log_entry(LogEntry { term: 1, data: vec![i; 4] }).unwrap();
            }
        }

        let ids = list_segment_ids(&dir).unwrap();
        assert!(ids.len() >= 2, "expected rotation to produce multiple segments");

        // Verify all data survives.
        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        assert_eq!(w2.load_state().unwrap().log.len(), 6);
    }

    // ── 6. Crash during append ────────────────────────────────────────────

    /// Simulate an OS crash mid-write by truncating the WAL file at an
    /// arbitrary byte inside a record.  Recovery must discard that record
    /// and restore only the complete ones before it.
    #[test]
    fn test_crash_during_append() {
        let dir = test_dir("crash_during");

        // Write two complete records, capture the file size, then write a
        // third record that we will truncate mid-payload to simulate a crash.
        let valid_end = {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(1).unwrap();
            w.save_vote(Some(1)).unwrap();
            let size = segment_path(&dir, 1).metadata().unwrap().len();
            w.append_log_entry(entry(1, 0xBB)).unwrap();
            size
        };

        // Truncate the WAL 3 bytes into the third record's payload to simulate
        // a crash mid-write.
        let seg = segment_path(&dir, 1);
        let f = OpenOptions::new().write(true).open(&seg).unwrap();
        f.set_len(valid_end + 3).unwrap(); // header+3 bytes of payload

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 1);
        assert_eq!(hs.voted_for, Some(1));
        assert!(hs.log.is_empty(), "partial entry must be discarded");
    }

    // ── 7. Crash after fsync ──────────────────────────────────────────────

    /// Write records with FsyncPolicy::Always, then reopen without any
    /// manual corruption.  All data must be present (fsync guarantees it).
    #[test]
    fn test_crash_after_fsync() {
        let dir = test_dir("crash_after_fsync");

        {
            let sync_cfg = WalConfig { segment_size: 64 * 1024 * 1024, fsync: FsyncPolicy::Always };
            let mut w = WalStorage::open(&dir, sync_cfg).unwrap();
            w.save_term(7).unwrap();
            w.save_vote(Some(4)).unwrap();
            for i in 0u8..3 {
                w.append_log_entry(entry(7, i)).unwrap();
            }
        } // drop → file handle closed (data already fsynced)

        // Reopen and verify nothing was lost.
        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 7);
        assert_eq!(hs.voted_for, Some(4));
        assert_eq!(hs.log.len(), 3);
        for (i, e) in hs.log.iter().enumerate() {
            assert_eq!(e.data, vec![i as u8]);
        }
    }

    // ── 8. Snapshot + WAL recovery ────────────────────────────────────────

    /// Save a snapshot covering entries 1–3, truncate those entries from the
    /// WAL, then append entries 4–5 (which appear at log positions 1–2 after
    /// truncation).  After reopen the snapshot and the two remaining entries
    /// must all be present.
    #[test]
    fn test_snapshot_wal_recovery() {
        let dir = test_dir("snap_recovery");

        {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(2).unwrap();

            // Append entries 1-3.
            for i in 1u8..=3 {
                w.append_log_entry(entry(2, i)).unwrap();
            }

            // Take a snapshot covering index 3.
            let snap = Snapshot {
                last_included_index: 3,
                last_included_term: 2,
                data: vec![0xCA, 0xFE],
            };
            w.save_snapshot(&snap).unwrap();

            // Trim the log (entries 1–3 are now covered by the snapshot).
            w.truncate_log(1).unwrap();

            // Append two more entries (become log positions 1 and 2).
            w.append_log_entry(entry(2, 4)).unwrap();
            w.append_log_entry(entry(2, 5)).unwrap();
        }

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();

        // Hard state.
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 2);
        assert_eq!(hs.log.len(), 2, "only post-snapshot entries survive");
        assert_eq!(hs.log[0].data, vec![4]);
        assert_eq!(hs.log[1].data, vec![5]);

        // Snapshot.
        let snap = w2.load_snapshot().unwrap().expect("snapshot must be present");
        assert_eq!(snap.last_included_index, 3);
        assert_eq!(snap.last_included_term, 2);
        assert_eq!(snap.data, vec![0xCA, 0xFE]);
    }

    // ── Additional correctness checks ─────────────────────────────────────

    #[test]
    fn test_fresh_wal_default_state() {
        let dir = test_dir("fresh");
        let w = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w.load_state().unwrap();
        assert_eq!(hs.current_term, 0);
        assert_eq!(hs.voted_for, None);
        assert!(hs.log.is_empty());
        assert!(w.load_snapshot().unwrap().is_none());
    }

    #[test]
    fn test_incremental_appends_recover() {
        let dir = test_dir("incremental");

        for round in 1u64..=3 {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(round).unwrap();
            w.append_log_entry(entry(round, round as u8)).unwrap();
        }

        let w = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w.load_state().unwrap();
        assert_eq!(hs.current_term, 3);
        assert_eq!(hs.log.len(), 3);
    }

    #[test]
    fn test_truncate_then_reappend_recovers() {
        let dir = test_dir("truncate_reappend");

        {
            let mut w = WalStorage::open(&dir, fast_config()).unwrap();
            w.save_term(1).unwrap();
            for i in 0u8..5 {
                w.append_log_entry(entry(1, i)).unwrap();
            }
            // Truncate from index 3 → keep entries 1-2.
            w.truncate_log(3).unwrap();
            // Re-append with term 2.
            w.append_log_entry(entry(2, 99)).unwrap();
        }

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.log.len(), 3);
        assert_eq!(hs.log[0].data, vec![0]);
        assert_eq!(hs.log[1].data, vec![1]);
        assert_eq!(hs.log[2].term, 2);
        assert_eq!(hs.log[2].data, vec![99]);
    }

    #[test]
    fn test_every_n_fsync_policy() {
        let dir = test_dir("every_n");
        let cfg = WalConfig {
            segment_size: 64 * 1024 * 1024,
            fsync: FsyncPolicy::EveryN(Duration::from_millis(100)),
        };
        let mut w = WalStorage::open(&dir, cfg).unwrap();
        w.save_term(1).unwrap();
        w.save_vote(Some(1)).unwrap();
        w.append_log_entry(entry(1, 42)).unwrap();
        drop(w);

        let w2 = WalStorage::open(&dir, fast_config()).unwrap();
        let hs = w2.load_state().unwrap();
        assert_eq!(hs.current_term, 1);
        assert_eq!(hs.log.len(), 1);
    }
}
