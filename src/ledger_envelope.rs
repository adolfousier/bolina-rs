//! In-memory evidence ledger (ledger.zig port, 333 lines).
//!
//! Hash store of accepted envelopes (BE-LEDGER-02), per-(sender,channel) replay
//! windows (BE-ENV-03/04), anchor table (BE-HIST-02), revocation table (BE-HIST-04).
//! Pure slice, no I/O; the DURABLE log is state/ledger.rs (separate module).
//! Powers admission checks in verify.rs (allParentsPresent precedes seq/insert: F5).

use crate::transport::replay::ReplayWindow;

// --- Constants (ledger.zig:26-34) ---
pub const HASH_BYTES: usize = 32;
pub const LEN_SIG_PUBKEY: usize = 32;
pub const LEN_CHANNEL_ID: usize = 32;
pub const MAX_ENVELOPES: usize = 4096;
pub const MAX_SEQ_WINDOWS: usize = 256;
pub const MAX_ANCHORS: usize = 256;
pub const MAX_REVOCATIONS: usize = 64;

// --- Errors (ledger.zig:40-47) — 6 variants, exhaustive ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    StoreFull,
    SeqWindowsFull,
    AnchorsFull,
    RevocationsFull,
    /// Same (sender, channel, seq) with different hash = equivocation (BE-ENV-05).
    Divergence,
    /// Seq below the window's lowest accepted = stale replay (BE-ENV-04).
    WindowStale,
}

pub type Result<T> = core::result::Result<T, LedgerError>;

// --- Entry types ---

/// An accepted envelope record: stored by HASH, not plaintext (BE-LEDGER-02).
#[derive(Clone)]
pub struct EnvelopeEntry {
    pub hash: [u8; HASH_BYTES],
    pub sender: [u8; LEN_SIG_PUBKEY],
    pub channel: [u8; LEN_CHANNEL_ID],
    pub seq: u64,
}

/// Per-(sender, channel) sequence window.
pub struct SeqWindow {
    pub sender: [u8; LEN_SIG_PUBKEY],
    pub channel: [u8; LEN_CHANNEL_ID],
    pub replay: ReplayWindow,
}

/// Anchor: first envelope of a pubkey is its anchor (BE-HIST-02).
#[derive(Clone)]
pub struct AnchorEntry {
    pub pubkey: [u8; LEN_SIG_PUBKEY],
    pub hash: [u8; HASH_BYTES],
}

/// Revocation record with cert expiry for F10 pruning.
#[derive(Clone)]
pub struct RevocationEntry {
    pub pubkey: [u8; LEN_SIG_PUBKEY],
    pub revoke_hash: [u8; HASH_BYTES],
    pub cert_expiry_ms: u64,
}

// --- The ledger ---

pub struct Ledger {
    envelopes: Vec<EnvelopeEntry>,
    seq_windows: Vec<SeqWindow>,
    anchors: Vec<AnchorEntry>,
    revocations: Vec<RevocationEntry>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            envelopes: Vec::with_capacity(MAX_ENVELOPES),
            seq_windows: Vec::with_capacity(MAX_SEQ_WINDOWS),
            anchors: Vec::with_capacity(MAX_ANCHORS),
            revocations: Vec::with_capacity(MAX_REVOCATIONS),
        }
    }

    pub fn envelope_count(&self) -> usize { self.envelopes.len() }
    pub fn seq_window_count(&self) -> usize { self.seq_windows.len() }
    pub fn anchor_count(&self) -> usize { self.anchors.len() }
    pub fn revocation_count(&self) -> usize { self.revocations.len() }

    /// Insert an envelope entry by hash.
    ///
    /// ORDER MATTERS (kill-proof): scan-first for matching (sender, channel, seq):
    /// - same hash → idempotent OK (return Ok without append)
    /// - different hash → Divergence (BE-ENV-05 equivocation)
    /// Only AFTER the scan: capacity check StoreFull, then append.
    /// A re-send of a stored envelope MUST succeed on a FULL store.
    pub fn insert_envelope(&mut self, entry: EnvelopeEntry) -> Result<()> {
        // Scan-first: dedupe check BEFORE capacity check.
        for existing in &self.envelopes {
            if existing.sender == entry.sender
                && existing.channel == entry.channel
                && existing.seq == entry.seq
            {
                if existing.hash == entry.hash {
                    return Ok(()); // idempotent
                } else {
                    return Err(LedgerError::Divergence); // equivocation
                }
            }
        }
        // Capacity check AFTER scan.
        if self.envelopes.len() >= MAX_ENVELOPES {
            return Err(LedgerError::StoreFull);
        }
        self.envelopes.push(entry);
        Ok(())
    }

    /// Check that every parent hash is present in the store (BE-LEDGER-01).
    /// In-memory check only; caller owns fetch budget.
    pub fn all_parents_present(&self, parents: &[[u8; HASH_BYTES]]) -> bool {
        parents.iter().all(|p| self.envelopes.iter().any(|e| &e.hash == p))
    }

    /// Check and advance the seq window for (sender, channel).
    /// - No window yet → create and seed with this seq ("first call seeds largest").
    /// - Seq below window → WindowStale (BE-ENV-04).
    /// - Seq accepted by ReplayWindow → Ok.
    pub fn check_seq(
        &mut self,
        sender: &[u8; LEN_SIG_PUBKEY],
        channel: &[u8; LEN_CHANNEL_ID],
        seq: u64,
    ) -> Result<()> {
        // Find existing window.
        let idx = self.seq_windows.iter().position(|w| {
            w.sender == *sender && w.channel == *channel
        });

        match idx {
            Some(i) => {
                // Existing window: check via ReplayWindow.
                if !self.seq_windows[i].replay.check(seq) {
                    return Err(LedgerError::WindowStale);
                }
                Ok(())
            }
            None => {
                // No window yet: create one and seed.
                if self.seq_windows.len() >= MAX_SEQ_WINDOWS {
                    return Err(LedgerError::SeqWindowsFull);
                }
                let mut rw = ReplayWindow::new();
                // First call seeds largest — ReplayWindow::check on first call
                // initialises with this seq as the largest.
                let _ = rw.check(seq);
                self.seq_windows.push(SeqWindow {
                    sender: *sender,
                    channel: *channel,
                    replay: rw,
                });
                Ok(())
            }
        }
    }

    /// Set the anchor for a pubkey (BE-HIST-02).
    /// FIRST envelope of a pubkey is its anchor.
    /// - First call for pubkey → store anchor, Ok.
    /// - Same hash → idempotent Ok.
    /// - Different hash → Divergence.
    pub fn set_anchor(
        &mut self,
        pubkey: &[u8; LEN_SIG_PUBKEY],
        hash: &[u8; HASH_BYTES],
    ) -> Result<()> {
        for a in &self.anchors {
            if a.pubkey == *pubkey {
                if a.hash == *hash {
                    return Ok(()); // idempotent
                } else {
                    return Err(LedgerError::Divergence);
                }
            }
        }
        if self.anchors.len() >= MAX_ANCHORS {
            return Err(LedgerError::AnchorsFull);
        }
        self.anchors.push(AnchorEntry {
            pubkey: *pubkey,
            hash: *hash,
        });
        Ok(())
    }

    /// Get the anchor hash for a pubkey. None if no anchor set.
    pub fn get_anchor(&self, pubkey: &[u8; LEN_SIG_PUBKEY]) -> Option<&[u8; HASH_BYTES]> {
        self.anchors.iter().find(|a| a.pubkey == *pubkey).map(|a| &a.hash)
    }

    /// Set a revocation record.
    /// - First call → store, Ok.
    /// - Same hash → idempotent Ok.
    /// - Different hash → Divergence.
    /// F10 pruning: when full, evict LOWEST cert_expiry_ms entry first.
    /// Full AND nothing prunable → RevocationsFull.
    pub fn set_revocation(
        &mut self,
        pubkey: &[u8; LEN_SIG_PUBKEY],
        revoke_hash: &[u8; HASH_BYTES],
        cert_expiry_ms: u64,
    ) -> Result<()> {
        // Check existing.
        for r in &self.revocations {
            if r.pubkey == *pubkey {
                if r.revoke_hash == *revoke_hash {
                    return Ok(()); // idempotent
                } else {
                    return Err(LedgerError::Divergence);
                }
            }
        }
        // Capacity: try F10 pruning.
        if self.revocations.len() >= MAX_REVOCATIONS {
            // Evict lowest cert_expiry_ms.
            if let Some(min_idx) = self
                .revocations
                .iter()
                .enumerate()
                .min_by_key(|(_, r)| r.cert_expiry_ms)
                .map(|(i, _)| i)
            {
                self.revocations.swap_remove(min_idx);
            } else {
                return Err(LedgerError::RevocationsFull);
            }
        }
        self.revocations.push(RevocationEntry {
            pubkey: *pubkey,
            revoke_hash: *revoke_hash,
            cert_expiry_ms,
        });
        Ok(())
    }

    /// Check if a pubkey is revoked.
    pub fn is_revoked(&self, pubkey: &[u8; LEN_SIG_PUBKEY]) -> bool {
        self.revocations.iter().any(|r| r.pubkey == *pubkey)
    }

    /// Get the revocation hash for a pubkey.
    pub fn get_revoke_hash(&self, pubkey: &[u8; LEN_SIG_PUBKEY]) -> Option<&[u8; HASH_BYTES]> {
        self.revocations.iter().find(|r| r.pubkey == *pubkey).map(|r| &r.revoke_hash)
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}
