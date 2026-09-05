//! W7 resolver: canonical resource identity (resolver.zig port).
//!
//! Non-surface, state over parsed values (D-018): consumes a proposed
//! resource_id byte string and returns the canonical form drawn from the
//! operator-declared set. The requester proposes, the executor resolves
//! (BE-RES-01).

use crate::state::intent;
use blake2::{Blake2s256, Digest};

// ---------------------------------------------------------------------------
// Constants (SPEC section 8.4 grammar).
// ---------------------------------------------------------------------------

pub const FP_BYTES: usize = 8;
pub const FP_HEX_LEN: usize = 16;
pub const NS_MAX: usize = 32;
pub const PATH_MAX: usize = 180;
pub const ID_MAX: usize = 4 + FP_HEX_LEN + 1 + NS_MAX + 1 + PATH_MAX;
pub const DOMAIN_RESOURCE_SET: u8 = 0x08;

pub const MAX_RESOURCES: usize = 32;
pub const MAX_ALIASES: usize = 64;

// ---------------------------------------------------------------------------
// ResolveError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    MalformedCanonical,
    SetFull,
    AliasPoolFull,
    DuplicateEntry,
    UnknownResource,
    AmbiguousResource,
    ForeignExecutor,
    BufferTooSmall,
}

// ---------------------------------------------------------------------------
// Entry + Alias
// ---------------------------------------------------------------------------

pub struct Entry {
    canonical: [u8; ID_MAX],
    len: usize,
}

pub struct Alias {
    bytes: [u8; ID_MAX],
    len: usize,
    entry: usize,
}

// ---------------------------------------------------------------------------
// executor_fp (BE-RES-06): BLAKE2s-256(sig_pubkey)[0..8], rendered as 16
// lowercase hex chars.
// ---------------------------------------------------------------------------

pub fn executor_fp(sig_pubkey: &[u8]) -> [u8; FP_HEX_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(sig_pubkey);
    let digest = hasher.finalize();
    let hex = b"0123456789abcdef";
    let mut out = [0u8; FP_HEX_LEN];
    for (i, &b) in digest[..FP_BYTES].iter().enumerate() {
        out[i * 2] = hex[(b >> 4) as usize];
        out[i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
    out
}

// ---------------------------------------------------------------------------
// validate_canonical (SPEC section 8.4 grammar):
// "bol:" fp "/" namespace "/" path
// ---------------------------------------------------------------------------

pub fn validate_canonical(id: &[u8]) -> bool {
    if id.len() < 4 + FP_HEX_LEN + 3 {
        return false;
    }
    if &id[..4] != b"bol:" {
        return false;
    }
    for &c in &id[4..4 + FP_HEX_LEN] {
        if !is_hex_lower(c) {
            return false;
        }
    }
    let mut pos = 4 + FP_HEX_LEN;
    if id[pos] != b'/' {
        return false;
    }
    pos += 1;
    let ns_start = pos;
    while pos < id.len() && id[pos] != b'/' {
        if !is_ns_char(id[pos]) {
            return false;
        }
        pos += 1;
    }
    let ns_len = pos - ns_start;
    if ns_len < 1 || ns_len > NS_MAX {
        return false;
    }
    if pos >= id.len() || id[pos] != b'/' {
        return false;
    }
    pos += 1;
    let path_start = pos;
    let mut seg_len: usize = 0;
    let mut dots: usize = 0;
    while pos < id.len() {
        let c = id[pos];
        if !is_path_char(c) && c != b'/' {
            return false;
        }
        if c == b'/' {
            if seg_len_invalid(seg_len, dots) {
                return false;
            }
            seg_len = 0;
            dots = 0;
        } else {
            seg_len += 1;
            if c == b'.' {
                dots += 1;
            }
        }
        pos += 1;
    }
    if seg_len_invalid(seg_len, dots) {
        return false;
    }
    let path_len = id.len() - path_start;
    path_len >= 1 && path_len <= PATH_MAX
}

fn seg_len_invalid(seg_len: usize, dots: usize) -> bool {
    seg_len == 0 || (dots == seg_len && seg_len <= 2)
}

fn is_hex_lower(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || (b'a'..=b'f').contains(&c)
}

fn is_ns_char(c: u8) -> bool {
    (b'a'..=b'z').contains(&c) || (b'0'..=b'9').contains(&c) || c == b'-'
}

fn is_path_char(c: u8) -> bool {
    is_ns_char(c) || c == b'.' || c == b'_'
}

// ---------------------------------------------------------------------------
// The Resolver
// ---------------------------------------------------------------------------

pub struct Resolver {
    own_fp: [u8; FP_HEX_LEN],
    entries: [Entry; MAX_RESOURCES],
    entry_count: usize,
    aliases: [Alias; MAX_ALIASES],
    alias_count: usize,
}

impl Default for Entry {
    fn default() -> Self {
        Self { canonical: [0u8; ID_MAX], len: 0 }
    }
}

impl Default for Alias {
    fn default() -> Self {
        Self { bytes: [0u8; ID_MAX], len: 0, entry: 0 }
    }
}

impl Resolver {
    pub fn new(sig_pubkey: &[u8]) -> Self {
        Self {
            own_fp: executor_fp(sig_pubkey),
            entries: std::array::from_fn(|_| Entry::default()),
            entry_count: 0,
            aliases: std::array::from_fn(|_| Alias::default()),
            alias_count: 0,
        }
    }

    pub fn add(&mut self, canonical: &[u8]) -> Result<(), ResolveError> {
        if !validate_canonical(canonical) {
            return Err(ResolveError::MalformedCanonical);
        }
        if canonical.len() > ID_MAX {
            return Err(ResolveError::MalformedCanonical);
        }
        if self.entry_count == MAX_RESOURCES {
            return Err(ResolveError::SetFull);
        }
        if self.find_entry(canonical).is_some() {
            return Err(ResolveError::DuplicateEntry);
        }
        let e = &mut self.entries[self.entry_count];
        e.canonical[..canonical.len()].copy_from_slice(canonical);
        e.len = canonical.len();
        self.entry_count += 1;
        Ok(())
    }

    pub fn add_alias(&mut self, canonical: &[u8], alias: &[u8]) -> Result<(), ResolveError> {
        if alias.is_empty() || alias.len() > ID_MAX {
            return Err(ResolveError::MalformedCanonical);
        }
        let idx = self.find_entry(canonical).ok_or(ResolveError::UnknownResource)?;
        if self.alias_count == MAX_ALIASES {
            return Err(ResolveError::AliasPoolFull);
        }
        let a = &mut self.aliases[self.alias_count];
        a.bytes[..alias.len()].copy_from_slice(alias);
        a.len = alias.len();
        a.entry = idx;
        self.alias_count += 1;
        Ok(())
    }

    pub fn resolve(&self, proposed: &[u8]) -> Result<&[u8], ResolveError> {
        let mut found: Option<usize> = None;
        for i in 0..self.entry_count {
            let e = &self.entries[i];
            let mut hit = e.len == proposed.len() && &e.canonical[..e.len] == proposed;
            if !hit {
                hit = self.alias_hits(i, proposed);
            }
            if hit {
                if let Some(f) = found {
                    if f != i {
                        return Err(ResolveError::AmbiguousResource);
                    }
                }
                if found.is_none() {
                    found = Some(i);
                }
            }
        }
        let idx = found.ok_or(ResolveError::UnknownResource)?;
        let c = &self.entries[idx].canonical[..self.entries[idx].len];
        if &c[4..4 + FP_HEX_LEN] != &self.own_fp {
            return Err(ResolveError::ForeignExecutor);
        }
        Ok(c)
    }

    pub fn serialized_len(&self) -> usize {
        let mut n = 0;
        for i in 0..self.entry_count {
            let e = &self.entries[i];
            n += 2 + e.len + 2;
            for a in &self.aliases[..self.alias_count] {
                if a.entry == i {
                    n += 2 + a.len;
                }
            }
        }
        n
    }

    pub fn serialize(&self, out: &mut [u8]) -> Result<usize, ResolveError> {
        if out.len() < self.serialized_len() {
            return Err(ResolveError::BufferTooSmall);
        }
        let mut pos = 0;
        for i in 0..self.entry_count {
            let e = &self.entries[i];
            out[pos..pos + 2].copy_from_slice(&(e.len as u16).to_be_bytes());
            pos += 2;
            out[pos..pos + e.len].copy_from_slice(&e.canonical[..e.len]);
            pos += e.len;
            let mut n_alias: usize = 0;
            for a in &self.aliases[..self.alias_count] {
                if a.entry == i {
                    n_alias += 1;
                }
            }
            out[pos..pos + 2].copy_from_slice(&(n_alias as u16).to_be_bytes());
            pos += 2;
            for a in &self.aliases[..self.alias_count] {
                if a.entry != i {
                    continue;
                }
                out[pos..pos + 2].copy_from_slice(&(a.len as u16).to_be_bytes());
                pos += 2;
                out[pos..pos + a.len].copy_from_slice(&a.bytes[..a.len]);
                pos += a.len;
            }
        }
        Ok(pos)
    }

    /// BE-RES-01/02/03/04: resolve then admit into the intent table.
    /// The entry admitted carries the canonical bytes, so the lock keys on
    /// the executor's form, never the requester's.
    pub fn resolve_and_admit(
        &self,
        table: &mut intent::Table,
        intent_id: &[u8; intent::LEN_INTENT_ID],
        resource_id: &[u8],
        now_ms: u64,
    ) -> Result<(), ResolveError> {
        let canonical = self.resolve(resource_id)?;
        let mut canonical_buf = [0u8; crate::codec::MAX_RESOURCE];
        if canonical.len() > canonical_buf.len() {
            return Err(ResolveError::MalformedCanonical);
        }
        canonical_buf[..canonical.len()].copy_from_slice(canonical);
        table.admit(intent_id, &canonical_buf, canonical.len(), now_ms)
            .map_err(|_| ResolveError::UnknownResource)
    }

    fn find_entry(&self, canonical: &[u8]) -> Option<usize> {
        for i in 0..self.entry_count {
            let e = &self.entries[i];
            if e.len == canonical.len() && &e.canonical[..e.len] == canonical {
                return Some(i);
            }
        }
        None
    }

    fn alias_hits(&self, entry_idx: usize, proposed: &[u8]) -> bool {
        for a in &self.aliases[..self.alias_count] {
            if a.entry == entry_idx && a.len == proposed.len() && &a.bytes[..a.len] == proposed {
                return true;
            }
        }
        false
    }
}
