//! Intent table: pending-intent pool, dedup + resource exclusivity (W3).
//! Sheet: specs/intent.md - Zig: src/intent.zig @ d24cf74.
//! BE-GRANT-04/06/06a/09/10 + MD4 compaction semantics (654a4af).

pub const T_PENDING_MS: u64 = 900_000; // BE-GRANT-06a default (intent.zig:45)
pub const MAX_PENDING: usize = 256; // overflow is a refusal, not a grow (intent.zig:46)
pub const LEN_INTENT_ID: usize = 16; // parser/channel.zig:37
pub const MAX_RESOURCE: usize = 256; // parser/channel.zig:28 (SPEC 6.3)

/// One class per BE-GRANT rule; closed set, no catch-all (D-049 analog).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    TableFull,
    DuplicateIntentId, // BE-GRANT-06b: intent_id already PENDING
    ResourceHeld,      // BE-GRANT-06: resource in PENDING or EXECUTING
    NotPending,        // transition attempted on a non-PENDING entry
}

/// Outcome of applying a Refusal (BE-GRANT-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalOutcome {
    Rejected,
    NoMatch, // dropped silently per BE-GRANT-09; still recorded here
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Executing, // grant verified, effect started (BE-GRANT-03a)
    Expired,   // T_pending fired or restart collapse (BE-GRANT-06a/04)
    Rejected,  // matched refusal, terminal (BE-GRANT-10)
}

/// Fixed-size copies: the table owns its bytes, borrows nothing (D-018 idiom).
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub intent_id: [u8; LEN_INTENT_ID],
    pub resource_id: [u8; MAX_RESOURCE],
    pub resource_len: usize,
    pub state: State,
    pub admitted_ms: u64,
}

pub struct Table {
    pub entries: Vec<Entry>, // hard-capped at MAX_PENDING; overflow refuses
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// BE-GRANT_04: a fresh table holds nothing (restart collapse).
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// BE-GRANT-06b + BE-GRANT-06: refuse duplicate PENDING intent_id, then a
    /// resource held in PENDING or EXECUTING, before any state mutates.
    pub fn admit(
        &mut self,
        intent_id: &[u8; LEN_INTENT_ID],
        resource: &[u8; MAX_RESOURCE],
        resource_len: usize,
        now_ms: u64,
    ) -> Result<(), IntentError> {
        debug_assert!(resource_len <= MAX_RESOURCE);
        if self.entries.iter().any(|e| e.state == State::Pending && e.intent_id == *intent_id) {
            return Err(IntentError::DuplicateIntentId);
        }
        if self.entries.iter().any(|e| {
            (e.state == State::Pending || e.state == State::Executing)
                && e.resource_id[..e.resource_len] == resource[..resource_len]
        }) {
            return Err(IntentError::ResourceHeld);
        }
        if self.entries.len() >= MAX_PENDING {
            return Err(IntentError::TableFull);
        }
        self.entries.push(Entry {
            intent_id: *intent_id,
            resource_id: *resource,
            resource_len,
            state: State::Pending,
            admitted_ms: now_ms,
        });
        Ok(())
    }

    /// THE one PENDING entry for this id (state filter is the contract that
    /// killed mutant d089/intent-terminality; never match Expired/Rejected).
    pub fn match_for_grant(&self, intent_id: &[u8; LEN_INTENT_ID]) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.state == State::Pending && e.intent_id == *intent_id)
    }

    /// PENDING -> EXECUTING; refused on any other source state (BE-GRANT-10).
    pub fn begin_executing(&mut self, idx: usize) -> Result<(), IntentError> {
        match self.entries.get_mut(idx) {
            Some(e) if e.state == State::Pending => {
                e.state = State::Executing;
                Ok(())
            }
            _ => Err(IntentError::NotPending),
        }
    }

    /// BE-GRANT_09: matched PENDING -> REJECTED (lock released); unmatched
    /// dropped. Outcome enum records which happened either way.
    pub fn apply_refusal(&mut self, intent_id: &[u8; LEN_INTENT_ID]) -> RefusalOutcome {
        match self.entries.iter().position(|e| e.state == State::Pending && e.intent_id == *intent_id) {
            Some(idx) => {
                self.entries[idx].state = State::Rejected;
                self.compact();
                RefusalOutcome::Rejected
            }
            None => RefusalOutcome::NoMatch,
        }
    }

    /// BE-GRANT-06a: PENDING entries past T_pending expire; expiry releases
    /// the lock AND (MD4) the slot. Executing entries never expire here
    /// (intent.zig:160-163: state == .pending is the only sweep target).
    pub fn expire_timeouts(&mut self, now_ms: u64) -> usize {
        let mut collapsed = 0;
        for e in self.entries.iter_mut() {
            if e.state == State::Pending && now_ms > e.admitted_ms + T_PENDING_MS {
                e.state = State::Expired;
                collapsed += 1;
            }
        }
        if collapsed > 0 {
            self.compact();
        }
        collapsed
    }

    /// MD4: dead slots hold no lock but held array capacity. Shift live
    /// survivors (PENDING/EXECUTING) to the front, preserving order.
    fn compact(&mut self) {
        self.entries.retain(|e| e.state == State::Pending || e.state == State::Executing);
    }
}
