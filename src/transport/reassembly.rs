//! reassembly.rs — BE-TR-05 fragmentation accounting (metadata-only)
//!
//! Port of src/reassembly.zig (240 lines) + reassembly_test.zig (125 lines).
//! Stores NO payload bytes — tracks fragment indices, byte accounting, timeouts,
//! node admission capacity. Caller owns byte buffers.
//!
//! TWO SCOPES, TWO FAILURE SEMANTICS:
//! - MESSAGE scope (per peer): drop THE MESSAGE, keep the session
//! - NODE scope: refuse NEW SESSIONS rather than degrade existing ones

// --- Constants (reassembly.zig:41-48) ---

pub const MAX_MESSAGE: usize = 1 << 20; // 1 MiB
pub const MAX_HEADER: usize = 512;
pub const MAX_BODY_LEN: usize = MAX_MESSAGE - MAX_HEADER;
pub const CONTEXTS_PER_PEER: u8 = 8;
pub const MEMORY_PER_PEER: usize = 8 << 20; // 8 MiB
pub const SESSIONS_PER_NODE: u16 = 512;
pub const MEMORY_PER_NODE: usize = 256 << 20; // 256 MiB
pub const INCOMPLETE_TIMEOUT_MS: u64 = 30_000;

// --- Events ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvent {
    Complete,
    Partial,
    Duplicate,
    MessageDropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEvent {
    Admitted,
    Refused,
}

// --- PeerReassembler (generic over context count + fragment ceiling) ---

#[derive(Clone, Copy)]
struct Context {
    msg_id: u64,
    total: u16,
    received: u16,
    bytes: usize,
    updated_ms: u64,
    in_use: bool,
    seen: [u64; 16], // up to 1024 fragments (16 * 64)
}

impl Context {
    fn new() -> Self {
        Self { msg_id: 0, total: 0, received: 0, bytes: 0, updated_ms: 0, in_use: false, seen: [0; 16] }
    }
}

pub struct PeerReassembler<const MAX_CONTEXTS: usize, const MAX_FRAGMENTS: u16> {
    contexts: [Context; MAX_CONTEXTS],
    active: u8,
    bytes_used: usize,
}

impl<const MAX_CONTEXTS: usize, const MAX_FRAGMENTS: u16> PeerReassembler<MAX_CONTEXTS, MAX_FRAGMENTS> {
    pub fn new() -> Self {
        Self { contexts: [Context::new(); MAX_CONTEXTS], active: 0, bytes_used: 0 }
    }

    pub fn active_contexts(&self) -> u8 { self.active }
    pub fn bytes_in_use(&self) -> usize { self.bytes_used }

    /// Ingest one authenticated fragment. Returns the outcome.
    /// Breach returns MessageDropped and tears down the context; session unaffected.
    pub fn ingest(&mut self, now_ms: u64, msg_id: u64, index: u16, total: u16, frag_bytes: usize) -> PeerEvent {
        // Malformed: total==0 | index>=total | total>ceiling
        if total == 0 || index >= total || total > MAX_FRAGMENTS {
            return PeerEvent::MessageDropped;
        }

        // Find existing context for msg_id
        let mut ctx_idx = None;
        for (i, c) in self.contexts.iter().enumerate() {
            if c.in_use && c.msg_id == msg_id {
                ctx_idx = Some(i);
                break;
            }
        }

        let creating = ctx_idx.is_none();
        if creating {
            // Find free slot
            for (i, c) in self.contexts.iter().enumerate() {
                if !c.in_use {
                    ctx_idx = Some(i);
                    break;
                }
            }
            if ctx_idx.is_none() {
                return PeerEvent::MessageDropped; // context limit
            }
        }

        let idx = ctx_idx.unwrap();
        let c = &mut self.contexts[idx];

        if creating {
            c.msg_id = msg_id;
            c.total = total;
            c.received = 0;
            c.bytes = 0;
            c.updated_ms = now_ms;
            c.in_use = true;
            c.seen = [0; 16];
            self.active += 1;
        } else if c.total != total {
            // Second fragment disagrees on total → free+drop
            self.free_context(idx);
            return PeerEvent::MessageDropped;
        }

        // Check duplicate
        let word = (index / 64) as usize;
        let bit = 1u64 << (index % 64);
        if (c.seen[word] & bit) != 0 {
            return PeerEvent::Duplicate;
        }

        // Check byte budget
        if c.bytes + frag_bytes > MAX_MESSAGE || self.bytes_used + frag_bytes > MEMORY_PER_PEER {
            self.free_context(idx);
            return PeerEvent::MessageDropped;
        }

        // Accept
        c.seen[word] |= bit;
        c.received += 1;
        c.bytes += frag_bytes;
        self.bytes_used += frag_bytes;
        c.updated_ms = now_ms;

        if c.received >= c.total {
            self.free_context(idx);
            PeerEvent::Complete
        } else {
            PeerEvent::Partial
        }
    }

    fn free_context(&mut self, idx: usize) {
        let c = &mut self.contexts[idx];
        if c.in_use {
            self.bytes_used = self.bytes_used.saturating_sub(c.bytes);
            c.in_use = false;
            self.active -= 1;
        }
    }

    /// Evict contexts older than INCOMPLETE_TIMEOUT_MS.
    pub fn evict_expired(&mut self, now_ms: u64) {
        for i in 0..MAX_CONTEXTS {
            if self.contexts[i].in_use {
                let age = now_ms.wrapping_sub(self.contexts[i].updated_ms);
                if age >= INCOMPLETE_TIMEOUT_MS {
                    self.free_context(i);
                }
            }
        }
    }
}

// --- NodeCapacity ---

pub struct NodeCapacity {
    sessions: u16,
    bytes: usize,
}

impl NodeCapacity {
    pub fn new() -> Self { Self { sessions: 0, bytes: 0 } }

    pub fn try_admit_session(&mut self) -> NodeEvent {
        if self.sessions >= SESSIONS_PER_NODE { return NodeEvent::Refused; }
        self.sessions += 1;
        NodeEvent::Admitted
    }

    pub fn release_session(&mut self) {
        self.sessions = self.sessions.saturating_sub(1);
    }

    pub fn within_memory(&self, additional: usize) -> bool {
        self.bytes + additional <= MEMORY_PER_NODE
    }

    pub fn add_bytes(&mut self, n: usize) {
        self.bytes = self.bytes.saturating_add(n);
    }

    pub fn release_bytes(&mut self, n: usize) {
        self.bytes = self.bytes.saturating_sub(n);
    }

    pub fn sessions(&self) -> u16 { self.sessions }
    pub fn bytes(&self) -> usize { self.bytes }
}
