//! Durable two-phase grant ledger (W3). Sheet: specs/grant_ledger.md.
//! Zig: src/grant_ledger.zig @ d24cf74 - BE-GRANT-01/01a, BE-REV-02, MD3,
//! F2 (buffer = actual file length), F3 (parent-dir fsync after rename),
//! F4 (durable first-receipt anchor), F6/D-090 (subject-expiry carried).
//!
//! Two-phase: COMMIT (consumed) -> PUBLISHED (tombstone). Un-tombstoned
//! commits after a crash are ORPHANS and re-emit their Effect exactly once
//! more on the next recover (at-least-once, fail-safe direction).
//! Single writer: exclusive flock at open (MD3). Read-only handles never
//! take the lock; their mutators fail DiskError.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use super::ffi;

pub const TAG_COMMIT: u8 = 0x01; // + grant_id(16) + expiry u64be = 25
pub const TAG_PUBLISHED: u8 = 0x02; // + grant_id(16) = 17
pub const TAG_REVOKE: u8 = 0x03; // + sig_pubkey(32) + cert_expiry u64be = 41
pub const TAG_FIRST_RECEIPT: u8 = 0x04; // + grant_id(16) + time u64be = 25
pub const REC_COMMIT_LEN: usize = 25;
pub const REC_PUBLISHED_LEN: usize = 17;
pub const REC_REVOKE_LEN: usize = 41;
pub const REC_FIRST_RECEIPT_LEN: usize = 25;
pub const MAX_LIVE: usize = 1024; // grant_ledger.zig:63 (consumed/revoked/published)
pub const GRANT_ID_LEN: usize = 16;
pub const SIG_PUBKEY_LEN: usize = 32;

/// Closed set; ORDER matters, mirrors Zig GrantLedgerError (line 86).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    BadLog,             // committed record failed parse outside trailing partial
    ResourceExhausted,  // live cap reached, prune did not free enough
    DiskError,          // I/O failure, or mutation through a read-only handle
    Locked,             // MD3: another descriptor holds the exclusive lock
}

pub struct Recovery {
    /// Consumed-but-never-published grant ids, in log insertion order.
    pub orphans: Vec<[u8; GRANT_ID_LEN]>,
    pub consumed_count: usize,
    pub revoked_count: usize,
}

pub struct GrantLedger {
    file: Option<File>,
    read_only: bool,
    path: PathBuf,
    // grant_id -> expiry_ms (live, un-tombstoned); cap MAX_LIVE (line 121)
    consumed: HashMap<[u8; GRANT_ID_LEN], u64>,
    consumed_order: Vec<[u8; GRANT_ID_LEN]>,
    published: HashSet<[u8; GRANT_ID_LEN]>, // cap MAX_LIVE (line 129)
    // signer pubkey -> cert_expiry_ms; NEVER pruned (BE-REV-02), cap MAX_LIVE
    revoked: HashMap<[u8; SIG_PUBKEY_LEN], u64>,
    // grant_id -> T_recv anchor; first sighting wins (F4)
    first_receipts: HashMap<[u8; GRANT_ID_LEN], u64>,
}

fn be64(buf: &[u8]) -> u64 {
    u64::from_be_bytes(buf.try_into().expect("len checked by caller"))
}

fn put_be64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

impl GrantLedger {
    /// Creates if absent; exclusive flock LOCK_EX|LOCK_NB -> Locked (MD3).
    /// Stale prune temp files are cleaned here (crash-during-prune, T8).
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        let file = OpenOptions::new().read(true).write(true).create(true).open(path)
            .map_err(|_| LedgerError::DiskError)?;
        if !ffi::flock_exclusive_nb(&file) {
            return Err(LedgerError::Locked); // file dropped: no lock leak
        }
        let stale = temp_path(path);
        if stale.exists() {
            std::fs::remove_file(&stale).map_err(|_| LedgerError::DiskError)?;
        }
        Ok(Self {
            file: Some(file),
            read_only: false,
            path: path.to_path_buf(),
            consumed: HashMap::new(),
            consumed_order: Vec::new(),
            published: HashSet::new(),
            revoked: HashMap::new(),
            first_receipts: HashMap::new(),
        })
    }

    /// MD3 audit view: NO lock; mutators fail DiskError through this handle.
    pub fn open_read_only(path: &Path) -> Result<Self, LedgerError> {
        let file = File::open(path).map_err(|_| LedgerError::DiskError)?;
        Ok(Self {
            file: Some(file),
            read_only: true,
            path: path.to_path_buf(),
            consumed: HashMap::new(),
            consumed_order: Vec::new(),
            published: HashSet::new(),
            revoked: HashMap::new(),
            first_receipts: HashMap::new(),
        })
    }

    /// Replay the log; the on-disk records are THE state (T2). A torn
    /// trailing record is discarded silently, never BadLog (T6). Unknown
    /// tags or short-but-complete-record corruption = BadLog.
    pub fn recover(&mut self) -> Result<Recovery, LedgerError> {
        let mut buf = Vec::new();
        let f = self.handle()?;
        f.seek(std::io::SeekFrom::Start(0)).map_err(|_| LedgerError::DiskError)?;
        f.read_to_end(&mut buf).map_err(|_| LedgerError::DiskError)?;
        // Full replay: the log is THE state; caches reset before rebuild.
        self.consumed.clear();
        self.consumed_order.clear();
        self.published.clear();
        self.revoked.clear();
        self.first_receipts.clear();
        let mut off = 0usize;
        while off < buf.len() {
            let remaining = buf.len() - off;
            let (need, tag) = match buf[off] {
                TAG_COMMIT => (REC_COMMIT_LEN, TAG_COMMIT),
                TAG_PUBLISHED => (REC_PUBLISHED_LEN, TAG_PUBLISHED),
                TAG_REVOKE => (REC_REVOKE_LEN, TAG_REVOKE),
                TAG_FIRST_RECEIPT => (REC_FIRST_RECEIPT_LEN, TAG_FIRST_RECEIPT),
                _ => return Err(LedgerError::BadLog),
            };
            if remaining < need {
                break; // torn trailing write: ignore tail (T6)
            }
            let rec = &buf[off..off + need];
            match tag {
                TAG_COMMIT => {
                    let mut id = [0u8; GRANT_ID_LEN];
                    id.copy_from_slice(&rec[1..1 + GRANT_ID_LEN]);
                    let expiry = be64(&rec[1 + GRANT_ID_LEN..]);
                    if !self.published.contains(&id) && !self.consumed.contains_key(&id) {
                        self.consumed_order.push(id);
                    }
                    self.consumed.insert(id, expiry);
                }
                TAG_PUBLISHED => {
                    let mut id = [0u8; GRANT_ID_LEN];
                    id.copy_from_slice(&rec[1..]);
                    self.consumed.remove(&id);
                    self.published.insert(id);
                }
                TAG_REVOKE => {
                    let mut pk = [0u8; SIG_PUBKEY_LEN];
                    pk.copy_from_slice(&rec[1..1 + SIG_PUBKEY_LEN]);
                    self.revoked.insert(pk, be64(&rec[1 + SIG_PUBKEY_LEN..]));
                }
                _ => {
                    // TAG_FIRST_RECEIPT: the anchor never moves (F4)
                    let mut id = [0u8; GRANT_ID_LEN];
                    id.copy_from_slice(&rec[1..1 + GRANT_ID_LEN]);
                    self.first_receipts.entry(id).or_insert(be64(&rec[1 + GRANT_ID_LEN..]));
                }
            }
            off += need;
        }
        Ok(Recovery {
            orphans: self
                .consumed_order
                .iter()
                .filter(|id| self.consumed.contains_key(*id))
                .copied()
                .collect(),
            consumed_count: self.consumed.len(),
            revoked_count: self.revoked.len(),
        })
    }

    /// Phase 1: mark a grant consumed. Idempotent: re-committing a spent
    /// (published) or already-committed id is a no-op (T7). fsync BEFORE the
    /// call returns (T1). Cap MAX_LIVE after an attempted prune.
    pub fn commit_consumed(
        &mut self,
        grant_id: &[u8; GRANT_ID_LEN],
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<(), LedgerError> {
        if self.consumed.contains_key(grant_id) || self.published.contains(grant_id) {
            return Ok(());
        }
        if self.consumed.len() >= MAX_LIVE {
            self.prune_expired(now_ms)?;
            if self.consumed.len() >= MAX_LIVE {
                return Err(LedgerError::ResourceExhausted);
            }
        }
        let mut rec = vec![TAG_COMMIT];
        rec.extend_from_slice(grant_id);
        put_be64(&mut rec, expiry_ms);
        self.append(&rec)?;
        self.consumed_order.push(*grant_id);
        self.consumed.insert(*grant_id, expiry_ms);
        Ok(())
    }

    /// Phase 2: tombstone. Re-publishing is a no-op (single row per id).
    pub fn mark_published(&mut self, grant_id: &[u8; GRANT_ID_LEN]) -> Result<(), LedgerError> {
        if self.published.contains(grant_id) {
            return Ok(());
        }
        let mut rec = vec![TAG_PUBLISHED];
        rec.extend_from_slice(grant_id);
        self.append(&rec)?;
        self.consumed.remove(grant_id);
        self.published.insert(*grant_id);
        Ok(())
    }

    /// Record a CA-signed revocation; subject cert-expiry rides along for
    /// pruning policy (F6/D-090). NEVER pruned (BE-REV-02, T4).
    pub fn commit_revocation(
        &mut self,
        sig_pubkey: &[u8; SIG_PUBKEY_LEN],
        cert_expiry_ms: u64,
    ) -> Result<(), LedgerError> {
        if self.revoked.contains_key(sig_pubkey) {
            return Ok(());
        }
        if self.revoked.len() >= MAX_LIVE {
            return Err(LedgerError::ResourceExhausted);
        }
        let mut rec = vec![TAG_REVOKE];
        rec.extend_from_slice(sig_pubkey);
        put_be64(&mut rec, cert_expiry_ms);
        self.append(&rec)?;
        self.revoked.insert(*sig_pubkey, cert_expiry_ms);
        Ok(())
    }

    /// F4: T_recv anchor, first sighting wins, survives restart (T10).
    pub fn record_first_receipt(&mut self, grant_id: &[u8; GRANT_ID_LEN], time_ms: u64) -> Result<(), LedgerError> {
        if self.first_receipts.contains_key(grant_id) {
            return Ok(());
        }
        let mut rec = vec![TAG_FIRST_RECEIPT];
        rec.extend_from_slice(grant_id);
        put_be64(&mut rec, time_ms);
        self.append(&rec)?;
        self.first_receipts.insert(*grant_id, time_ms);
        Ok(())
    }

    pub fn get_first_receipt(&self, grant_id: &[u8; GRANT_ID_LEN]) -> Option<u64> {
        self.first_receipts.get(grant_id).copied()
    }

    pub fn is_consumed(&self, grant_id: &[u8; GRANT_ID_LEN]) -> bool {
        self.consumed.contains_key(grant_id)
    }

    pub fn is_published(&self, grant_id: &[u8; GRANT_ID_LEN]) -> bool {
        self.published.contains(grant_id)
    }

    pub fn is_revoked(&self, sig_pubkey: &[u8; SIG_PUBKEY_LEN]) -> bool {
        self.revoked.contains_key(sig_pubkey)
    }

    /// Drop expired consumed grants (T5); rewrite atomically: temp + fsync +
    /// rename + parent-dir fsync (F3, T8), reopen and RE-FLOCK (MD3).
    pub fn prune_expired(&mut self, now_ms: u64) -> Result<(), LedgerError> {
        if self.read_only {
            return Err(LedgerError::DiskError);
        }
        let expired: Vec<[u8; GRANT_ID_LEN]> = self
            .consumed
            .iter()
            .filter(|(_, &exp)| exp <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        for id in &expired {
            self.consumed.remove(id);
        }
        self.consumed_order.retain(|id| self.consumed.contains_key(id));

        // Rebuild the canonical image: live commits + revocations + anchors.
        let mut image = Vec::new();
        for (id, exp) in &self.consumed {
            image.push(TAG_COMMIT);
            image.extend_from_slice(id);
            put_be64(&mut image, *exp);
        }
        for (pk, exp) in &self.revoked {
            image.push(TAG_REVOKE);
            image.extend_from_slice(pk);
            put_be64(&mut image, *exp);
        }
        for (id, t) in &self.first_receipts {
            image.push(TAG_FIRST_RECEIPT);
            image.extend_from_slice(id);
            put_be64(&mut image, *t);
        }

        let tmp = temp_path(&self.path);
        {
            let mut tf = File::create(&tmp).map_err(|_| LedgerError::DiskError)?;
            tf.write_all(&image).map_err(|_| LedgerError::DiskError)?;
            tf.sync_all().map_err(|_| LedgerError::DiskError)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|_| LedgerError::DiskError)?;
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all(); // F3: durability of the rename itself
            }
        }
        // Reopen the new inode and re-take the exclusive lock (MD3).
        self.file = None;
        let file = OpenOptions::new().read(true).write(true).open(&self.path)
            .map_err(|_| LedgerError::DiskError)?;
        if !ffi::flock_exclusive_nb(&file) {
            return Err(LedgerError::Locked);
        }
        self.file = Some(file);
        Ok(())
    }

    /// Releases the exclusive lock (T9 second half).
    pub fn close(&mut self) {
        self.file = None;
    }

    fn handle(&mut self) -> Result<&mut File, LedgerError> {
        self.file.as_mut().ok_or(LedgerError::DiskError)
    }

    /// fsync BEFORE the record is considered written (T1). Read-only
    /// handles refuse mutators with DiskError (MD3 contract).
    fn append(&mut self, rec: &[u8]) -> Result<(), LedgerError> {
        if self.read_only {
            return Err(LedgerError::DiskError);
        }
        let f = self.handle()?;
        f.write_all(rec).map_err(|_| LedgerError::DiskError)?;
        f.sync_all().map_err(|_| LedgerError::DiskError)
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".prune-tmp");
    PathBuf::from(s)
}
