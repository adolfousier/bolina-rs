#![allow(dead_code)]
//! sync.rs — BE-SYNC-01..05 admission + rate budget + response builder
//!
//! Port of src/sync.zig (289 lines) + sync_test.zig (8 named tests).

// --- Constants (sync.zig:33-41) ---

pub const MAX_RESPONSE_ENVELOPES: usize = 64;
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;
pub const RESPONSE_HEADER: usize = 34;
pub const WALK_MAX_DEPTH: usize = 128;
pub const WALK_MAX_TOTAL: usize = 4096;
pub const RATE_WINDOW_MS: u64 = 10_000;
pub const SERVE_BUDGET: usize = 8;
pub const ISSUE_BUDGET: usize = 4;
pub const MAX_TRACKED_PEERS: usize = 64;

// --- Error set (sync.zig:43) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    NoSession,
    NotMember,
    Revoked,
    RateLimited,
    WalkExhausted,
    BadEnvelope,
    BufferTooSmall,
}

pub type Result<T> = std::result::Result<T, SyncError>;

// --- RateWindow (BE-SYNC-04) ---

pub struct RateWindow {
    stamps: [u64; SERVE_BUDGET],
    budget: usize,
    next: usize,
}

impl RateWindow {
    pub fn new(budget: usize) -> Self {
        Self { stamps: [0; SERVE_BUDGET], budget, next: 0 }
    }

    /// Admit iff fewer than `budget` recorded events lie inside the window.
    pub fn admit(&mut self, window_ms: u64, now_ms: u64) -> bool {
        let mut inside = 0;
        for i in 0..self.budget {
            let s = self.stamps[i];
            if s != 0 && now_ms >= s && now_ms - s < window_ms {
                inside += 1;
            }
        }
        if inside >= self.budget { return false; }
        self.stamps[self.next] = now_ms;
        self.next = (self.next + 1) % self.budget;
        true
    }
}

// --- RateTable (per-peer windows, fail closed) ---

pub struct RateTable {
    peers: [[u8; 32]; MAX_TRACKED_PEERS],
    windows: [RateWindow; MAX_TRACKED_PEERS],
    budget: usize,
    used: usize,
}

impl RateTable {
    pub fn new(budget: usize) -> Self {
        Self {
            peers: [[0; 32]; MAX_TRACKED_PEERS],
            windows: std::array::from_fn(|_| RateWindow::new(budget)),
            budget,
            used: 0,
        }
    }

    /// Admit a peer's request iff within budget. Full table refuses new peers.
    pub fn admit(&mut self, peer: [u8; 32], window_ms: u64, now_ms: u64) -> bool {
        for i in 0..self.used {
            if self.peers[i] == peer {
                return self.windows[i].admit(window_ms, now_ms);
            }
        }
        if self.used >= MAX_TRACKED_PEERS { return false; }
        self.peers[self.used] = peer;
        self.used += 1;
        self.windows[self.used - 1].admit(window_ms, now_ms)
    }

    pub fn used(&self) -> usize { self.used }
}

// --- ServeItem + BuildResult (BE-SYNC-02) ---

#[derive(Clone)]
pub struct ServeItem {
    pub hash: [u8; 32],
    pub wire: Vec<u8>,
}

pub struct BuildResult {
    pub count: usize,
    pub truncated: bool,
    pub bytes_written: usize,
}

// --- Response builder (BE-SYNC-02) ---

/// Build a sync response: header (34 bytes) + envelopes, hard bounds.
/// Returns BuildResult with count, truncated flag, bytes written.
pub fn build_response(
    out: &mut [u8],
    channel_id: [u8; 32],
    items: &[ServeItem],
    have_hashes: &[[u8; 32]],
) -> BuildResult {
    if out.len() < RESPONSE_HEADER {
        return BuildResult { count: 0, truncated: false, bytes_written: 0 };
    }
    out[0] = 1; // version
    out[1..33].copy_from_slice(&channel_id);
    let mut pos = RESPONSE_HEADER;
    let mut count = 0usize;
    let mut truncated = false;

    for item in items {
        if have_hashes.iter().any(|h| *h == item.hash) {
            continue; // peer already has this
        }
        let need = item.wire.len();
        if count >= MAX_RESPONSE_ENVELOPES || pos + need + 1 > MAX_RESPONSE_BYTES {
            truncated = true;
            break;
        }
        out[pos..pos + need].copy_from_slice(&item.wire);
        pos += need;
        count += 1;
    }

    out[33] = count as u8;
    BuildResult { count, truncated, bytes_written: pos }
}
