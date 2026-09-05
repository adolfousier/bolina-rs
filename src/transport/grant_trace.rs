//! W8 grant_trace: test-only conformance trace instrument (grant_trace.zig port).
//!
//! bolina.grant-trace.v1: comptime-gated instrumentation for TLA conformance.
//! When disabled (default), every emit call site compiles out: zero cost.
//! When enabled via feature "tla-trace", events append to a fixed ring buffer.
//!
//! Event contract (load-bearing):
//!   commit_consumed_11 emitted ONLY after durable appendSync returns OK.
//!   effect_start IS the normative APPROVED->EXECUTING transition (D-067).
//!   effect_refused: refused path never emits mark_published afterwards.

// ---------------------------------------------------------------------------
// Tag enum: wire-stable ids (numbering matches Zig for cross-impl comparison).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    ReceiveIntent = 1,
    RejectResourceConflict = 2,
    BeginVerify = 3,
    VerifyCheck = 4,
    CommitConsumed11 = 5,
    EffectStart = 6,
    EffectReturn = 7,
    MarkPublished = 8,
    RecordExecutingWitness = 9,
    RecoverMarkPublished = 10,
    EffectRefused = 11,
    PublishOutcome = 12,
    MarkPublishedFailed = 13,
    PruneTempWritten = 14,
    PruneTempSynced = 15,
    PruneRenamed = 16,
    PruneReopened = 17,
    ExpirePending = 18,
    TraceOverflow = 255,
}

pub const NO_PC: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Event: fixed-size record.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub tag: Tag,
    pub pc: u8,
    pub id: u64,
    pub id2: u64,
    pub now_ms: u64,
    pub seq: u32,
}

pub const CAP: usize = 256;
pub const SCHEMA: &str = "bolina.grant-trace.v1";

// ---------------------------------------------------------------------------
// FNV-1a fingerprint: deterministic across runs and builds.
// ---------------------------------------------------------------------------

pub fn fingerprint(id: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in id {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ---------------------------------------------------------------------------
// TraceRing: fixed-capacity event buffer.
// ---------------------------------------------------------------------------

pub struct TraceRing {
    events: [Event; CAP],
    len: usize,
    seq_next: u32,
    overflow_count: usize,
}

impl Default for TraceRing {
    fn default() -> Self {
        Self {
            events: [Event {
                tag: Tag::ReceiveIntent,
                pc: 0,
                id: 0,
                id2: 0,
                now_ms: 0,
                seq: 0,
            }; CAP],
            len: 0,
            seq_next: 0,
            overflow_count: 0,
        }
    }
}

impl TraceRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn emit(&mut self, tag: Tag, pc: u8, id_bytes: &[u8], now_ms: u64) {
        self.emit2(tag, pc, id_bytes, &[], now_ms);
    }

    pub fn emit2(&mut self, tag: Tag, pc: u8, id_bytes: &[u8], id2_bytes: &[u8], now_ms: u64) {
        if self.len == CAP {
            if self.overflow_count == 0 {
                // Exactly one marker on first overflow
                self.events[CAP - 1] = Event {
                    tag: Tag::TraceOverflow,
                    pc: NO_PC,
                    id: 0,
                    id2: 0,
                    now_ms,
                    seq: self.seq_next,
                };
                self.seq_next += 1;
            }
            self.overflow_count += 1;
            return;
        }
        self.events[self.len] = Event {
            tag,
            pc,
            id: fingerprint(id_bytes),
            id2: if id2_bytes.is_empty() { 0 } else { fingerprint(id2_bytes) },
            now_ms,
            seq: self.seq_next,
        };
        self.seq_next += 1;
        self.len += 1;
    }

    pub fn snapshot(&self) -> &[Event] {
        &self.events[..self.len]
    }

    pub fn overflow(&self) -> usize {
        self.overflow_count
    }

    pub fn reset(&mut self) {
        self.len = 0;
        self.seq_next = 0;
        self.overflow_count = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
