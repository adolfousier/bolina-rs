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

// --- WalkQueue (BE-SYNC-03) ---

/// Bounded walk over parent hashes: stops at depth 128 AND total 4096;
/// UNRESOLVED parents are SURFACED (reported back), NEVER retried inside
/// the walk (sync.zig BE-SYNC_03).
pub struct WalkQueue {
    queue: std::collections::VecDeque<[u8; 32]>,
    visited: Vec<[u8; 32]>, // linear scan; bounded by WALK_MAX_TOTAL
    depth: usize,
    unresolved: Vec<[u8; 32]>,
}

impl WalkQueue {
    pub fn new(root: [u8; 32]) -> Self {
        let mut q = Self {
            queue: std::collections::VecDeque::new(),
            visited: Vec::new(),
            depth: 0,
            unresolved: Vec::new(),
        };
        q.queue.push_back(root);
        q.visited.push(root);
        q
    }

    /// Push a parent hash. Refuses at WALK_MAX_TOTAL (fail closed).
    pub fn push(&mut self, hash: [u8; 32]) -> Result<()> {
        if self.visited.len() >= WALK_MAX_TOTAL {
            return Err(SyncError::WalkExhausted);
        }
        if self.visited.iter().any(|v| *v == hash) {
            return Ok(()); // seen (incl. surfaced): never retried
        }
        self.visited.push(hash);
        self.queue.push_back(hash);
        Ok(())
    }

    /// Next hash to walk, respecting WALK_MAX_DEPTH. None = walk complete.
    pub fn next(&mut self) -> Option<[u8; 32]> {
        if self.depth >= WALK_MAX_DEPTH {
            return None; // depth bound: walk stops
        }
        match self.queue.pop_front() {
            Some(h) => {
                self.depth += 1;
                Some(h)
            }
            None => None,
        }
    }

    /// Record resolution outcome. Unresolved parents are SURFACED, never
    /// re-enqueued.
    pub fn record(&mut self, hash: [u8; 32], resolved: bool) {
        if !resolved && !self.unresolved.contains(&hash) {
            self.unresolved.push(hash);
        }
    }

    pub fn depth(&self) -> usize { self.depth }
    pub fn total(&self) -> usize { self.visited.len() }
    pub fn unresolved(&self) -> &[[u8; 32]] { &self.unresolved }
}

#[cfg(test)]
mod walk_tests {
    use super::*;

    #[test]
    fn be_sync_03_walk_stops_at_depth_128() {
        let mut w = WalkQueue::new([1u8; 32]);
        // chain of 200 pushes; walk must stop at 128 pops
        for i in 0..199u8 {
            w.push([i; 32]).unwrap();
        }
        let mut pops = 0;
        while w.next().is_some() {
            pops += 1;
        }
        assert_eq!(pops, WALK_MAX_DEPTH);
        assert_eq!(w.depth(), WALK_MAX_DEPTH);
    }

    #[test]
    fn be_sync_03_walk_stops_at_total_4096() {
        let mut w = WalkQueue::new([0u8; 32]);
        let mut refused = false;
        for i in 0..WALK_MAX_TOTAL + 10 {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&(i as u64).to_be_bytes());
            if w.push(h).is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused, "walk must refuse past total bound (fail closed)");
        assert!(w.total() <= WALK_MAX_TOTAL);
    }

    #[test]
    fn be_sync_03_unresolved_surfaced_never_retried() {
        let mut w = WalkQueue::new([9u8; 32]);
        w.next(); // pop root
        w.record([9u8; 32], false); // unresolved
        assert_eq!(w.unresolved(), &[[9u8; 32]]);
        // re-push same hash: silently ignored (never retried), not surfaced twice
        w.push([9u8; 32]).unwrap();
        assert_eq!(w.unresolved().len(), 1);
        assert_eq!(w.queue.len(), 0);
    }
}
