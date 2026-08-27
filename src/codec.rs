//! codec — post-authentication channel wire formats (W2).
//!
//! Port of `src/parser/channel.zig` + `src/parser/session.zig` (cert) +
//! `verify.verifySigned`. Zero-alloc parsers: every returned slice aliases the
//! caller buffer, one central `Cursor::need` exit (BE-WIRE-02 as construction).
//! Big-endian everywhere; version parsed, never rejected (SPEC 2.2).
//!
//! Invariants inherited from the Zig reference (specs/*.md sheets):
//! - `Oversize` checked BEFORE any large read (env_body, cert_scope, ...).
//! - Trailing-bytes totality: exactly one message per buffer, except spans
//!   (inline in Effects, no trailing check on the shared-cursor path).
//! - CA keys strictly ascending: a PARSE failure, not policy (SPEC 3.1).
//! - `Malformed` is only wrong-type/reserved bytes on the transport half;
//!   channel structures never emit it.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// --- limits (SPEC BE-TR-05 / 6.3 / 7 / 8.1 / 3.1) ---------------------------

pub const MAX_MESSAGE: usize = 1 << 20;
pub const LEN_PUBKEY: usize = 32;
pub const LEN_SIG: usize = 64;
pub const MAX_HEADER: usize = 512;
pub const MAX_BODY: u32 = (MAX_MESSAGE - MAX_HEADER) as u32;
pub const MAX_PARENTS: u8 = 4;
pub const MAX_RESOURCE: usize = 256;
pub const MAX_ACTION: u32 = 256 * 1024;
pub const MAX_RATIONALE: usize = 4 * 1024;
pub const MAX_NOTE: usize = 1024;
pub const MAX_NAME: usize = 64;
pub const MAX_SCOPE: u8 = 8;
pub const MAX_CA_SIGS: u8 = 4;

pub const LEN_CHANNEL_ID: usize = 32;
pub const LEN_PARENT: usize = 32;
pub const LEN_INTENT_ID: usize = 16;
pub const LEN_GRANT_ID: usize = 16;
pub const LEN_ACTION_DIGEST: usize = 32;
pub const LEN_SCOPE_ID: usize = 8;
pub const LEN_SPAN_REF: usize = 16;
pub const LEN_CA_KEY: usize = 32;

pub const LEN_SPAN_ID: usize = 16;
pub const LEN_TRACE_ID: usize = 16;
pub const LEN_ORIGIN: usize = 32;
pub const LEN_DIGEST: usize = 32;

// Domain tags (SPEC BE-SIG-01). Verifier prefixes tag || tbs.
pub const DOMAIN_CERT: u8 = 0x01;
pub const DOMAIN_ENVELOPE: u8 = 0x02;
pub const DOMAIN_SPAN: u8 = 0x03;
pub const DOMAIN_GRANT: u8 = 0x04;
pub const DOMAIN_REFUSAL: u8 = 0x06;

// Envelope body types (SPEC 6.3).
pub const BODY_UTTERANCE: u8 = 1;
pub const BODY_INTENT: u8 = 2;
pub const BODY_GRANT: u8 = 3;

// --- errors (exact set, no extras; D-049 analog) ----------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer ended before a fixed field completed.
    Truncated,
    /// An attacker-influenced length exceeded its declared bound, checked
    /// BEFORE the payload read.
    Oversize,
    /// BE-WIRE-02 totality: bytes after the one expected message.
    TrailingBytes,
    /// Structural canonicity failure: CA keys not strictly ascending, or
    /// ca_sig_count zero.
    Malformed,
}

// --- cursor: every exit routes through need() -------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    /// The ONE truncation exit point (BE-WIRE-02).
    fn need(&self, n: usize) -> Result<(), ParseError> {
        if self.buf.len() - self.pos >= n {
            Ok(())
        } else {
            Err(ParseError::Truncated)
        }
    }
    fn u8r(&mut self) -> Result<u8, ParseError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16be(&mut self) -> Result<u16, ParseError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u32be(&mut self) -> Result<u32, ParseError> {
        self.need(4)?;
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    fn u64be(&mut self) -> Result<u64, ParseError> {
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(b))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    /// Length-prefixed field with u16 length, bound checked first.
    fn field16(&mut self, max: usize) -> Result<&'a [u8], ParseError> {
        let len = self.u16be()? as usize;
        if len > max {
            return Err(ParseError::Oversize);
        }
        self.take(len)
    }
    /// Length-prefixed field with u32 length, bound checked first.
    fn field32(&mut self, max: u32) -> Result<&'a [u8], ParseError> {
        let len = self.u32be()?;
        if len > max {
            return Err(ParseError::Oversize);
        }
        self.take(len as usize)
    }
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

// --- structures (all borrow the input; zero allocation) ---------------------

#[derive(Debug)]
pub struct Envelope<'a> {
    pub version: u8,
    pub channel_id: &'a [u8],
    pub sender: &'a [u8],
    pub seq: u64,
    pub parent_count: u8,
    pub parents: &'a [u8],
    pub ts: u64,
    pub body_type: u8,
    pub body: &'a [u8],
    pub tbs: &'a [u8],
    pub sig: &'a [u8],
}

#[derive(Debug)]
pub struct Intent<'a> {
    pub intent_id: &'a [u8],
    pub resource_id: &'a [u8],
    pub action: &'a [u8],
    pub rationale: &'a [u8],
}

#[derive(Debug)]
pub struct Grant<'a> {
    pub version: u8,
    pub grant_id: &'a [u8],
    pub intent_id: &'a [u8],
    pub approver: &'a [u8],
    pub subject: &'a [u8],
    pub executor: &'a [u8],
    pub resource_id: &'a [u8],
    pub action_digest: &'a [u8],
    pub not_after: u64,
    pub tbs: &'a [u8],
    pub sig: &'a [u8],
}

#[derive(Debug)]
pub struct Refusal<'a> {
    pub intent_id: &'a [u8],
    pub note: &'a [u8],
    pub tbs: &'a [u8],
    pub sig: &'a [u8],
}

#[derive(Debug)]
pub struct Span<'a> {
    pub version: u8,
    pub span_id: &'a [u8],
    pub trace_id: &'a [u8],
    pub resource_id: &'a [u8],
    pub method_id: u8,
    pub volatility: u8,
    pub origin: &'a [u8],
    pub observed_at: u64,
    pub digest: &'a [u8],
    pub executor: &'a [u8],
    pub tbs: &'a [u8],
    pub sig: &'a [u8],
}

#[derive(Debug)]
pub struct Cert<'a> {
    pub version: u8,
    pub role_bits: u8,
    pub sig_pubkey: &'a [u8],
    pub kex_pubkey: &'a [u8],
    pub not_before: u64,
    pub not_after: u64,
    pub name: &'a [u8],
    pub scope_count: u8,
    pub scope_ids: &'a [u8],
    pub ca_sig_count: u8,
    pub ca_sigs: &'a [u8],
    pub tbs: &'a [u8],
}

// --- parsers ----------------------------------------------------------------

/// Envelope (SPEC 6.2/6.3):
/// u8 version | [32] channel_id | [32] sender | u64 seq | u8 parent_count(<=4)
/// parents | u64 ts | u8 body_type | u32 body_len(<=MAX_BODY) body | [64] sig
pub fn parse_envelope(buf: &[u8]) -> Result<Envelope<'_>, ParseError> {
    let mut c = Cursor::new(buf);
    let version = c.u8r()?;
    let channel_id = c.take(LEN_CHANNEL_ID)?;
    let sender = c.take(LEN_PUBKEY)?;
    let seq = c.u64be()?;
    let parent_count = c.u8r()?;
    if parent_count > MAX_PARENTS {
        return Err(ParseError::Oversize);
    }
    let parents = c.take(parent_count as usize * LEN_PARENT)?;
    let ts = c.u64be()?;
    let body_type = c.u8r()?;
    let body_len = c.u32be()?;
    if body_len > MAX_BODY {
        return Err(ParseError::Oversize);
    }
    let body = c.take(body_len as usize)?;
    let tbs = &buf[0..c.pos];
    let sig = c.take(LEN_SIG)?;
    if !c.rest().is_empty() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Envelope {
        version,
        channel_id,
        sender,
        seq,
        parent_count,
        parents,
        ts,
        body_type,
        body,
        tbs,
        sig,
    })
}

/// Intent body (SPEC 6.3):
/// [16] intent_id | u16 resource_len resource(<=256)
/// u32 action_len action(<=256KiB, OPAQUE) | u16 rationale_len rationale(<=4KiB)
pub fn parse_intent(buf: &[u8]) -> Result<Intent<'_>, ParseError> {
    let mut c = Cursor::new(buf);
    let intent_id = c.take(LEN_INTENT_ID)?;
    let resource_id = c.field16(MAX_RESOURCE)?;
    let action = c.field32(MAX_ACTION)?;
    let rationale = c.field16(MAX_RATIONALE)?;
    if !c.rest().is_empty() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Intent {
        intent_id,
        resource_id,
        action,
        rationale,
    })
}

/// Grant (SPEC 8.1):
/// u8 version | [16] grant_id | [16] intent_id | [32] approver | [32] subject
/// [32] executor | u16 resource_len resource | [32] action_digest
/// u64 not_after | [64] sig
pub fn parse_grant(buf: &[u8]) -> Result<Grant<'_>, ParseError> {
    let mut c = Cursor::new(buf);
    let version = c.u8r()?;
    let grant_id = c.take(LEN_GRANT_ID)?;
    let intent_id = c.take(LEN_INTENT_ID)?;
    let approver = c.take(LEN_PUBKEY)?;
    let subject = c.take(LEN_PUBKEY)?;
    let executor = c.take(LEN_PUBKEY)?;
    let resource_id = c.field16(MAX_RESOURCE)?;
    let action_digest = c.take(LEN_ACTION_DIGEST)?;
    let not_after = c.u64be()?;
    let tbs = &buf[0..c.pos];
    let sig = c.take(LEN_SIG)?;
    if !c.rest().is_empty() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Grant {
        version,
        grant_id,
        intent_id,
        approver,
        subject,
        executor,
        resource_id,
        action_digest,
        not_after,
        tbs,
        sig,
    })
}

/// Refusal (SPEC 8.5): [16] intent_id | u16 note_len note(<=1KiB) | [64] sig.
/// No version field; binding content is intent_id alone.
pub fn parse_refusal(buf: &[u8]) -> Result<Refusal<'_>, ParseError> {
    let mut c = Cursor::new(buf);
    let intent_id = c.take(LEN_INTENT_ID)?;
    let note = c.field16(MAX_NOTE)?;
    let tbs = &buf[0..c.pos];
    let sig = c.take(LEN_SIG)?;
    if !c.rest().is_empty() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Refusal {
        intent_id,
        note,
        tbs,
        sig,
    })
}

/// Span body (SPEC 7.1):
/// u8 version | [16] span_id | [16] trace_id | u16 resource_len resource
/// u8 method_id | u8 volatility | [32] origin | u64 observed_at
/// [32] digest | [32] executor | [64] sig
pub fn parse_span(buf: &[u8]) -> Result<Span<'_>, ParseError> {
    let mut c = Cursor::new(buf);
    let version = c.u8r()?;
    let span_id = c.take(LEN_SPAN_ID)?;
    let trace_id = c.take(LEN_TRACE_ID)?;
    let resource_id = c.field16(MAX_RESOURCE)?;
    let method_id = c.u8r()?;
    let volatility = c.u8r()?;
    let origin = c.take(LEN_ORIGIN)?;
    let observed_at = c.u64be()?;
    let digest = c.take(LEN_DIGEST)?;
    let executor = c.take(LEN_PUBKEY)?;
    let tbs = &buf[0..c.pos];
    let sig = c.take(LEN_SIG)?;
    if !c.rest().is_empty() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Span {
        version,
        span_id,
        trace_id,
        resource_id,
        method_id,
        volatility,
        origin,
        observed_at,
        digest,
        executor,
        tbs,
        sig,
    })
}

/// Certificate (SPEC 3.1):
/// u8 version | u8 role | [32] sig_pub | [32] kex_pub | u64 not_before
/// u64 not_after | u16 name_len name(<=64) | u8 scope_count(<=8) scopes
/// u8 ca_sig_count(1..4) | ([32] ca_key + [64] ca_sig)*, keys STRICTLY
/// ascending (parse failure otherwise). tbs = bytes before ca_sig_count.
pub fn parse_cert(buf: &[u8]) -> Result<Cert<'_>, ParseError> {
    let mut c = Cursor::new(buf);
    let version = c.u8r()?;
    let role_bits = c.u8r()?;
    let sig_pubkey = c.take(LEN_PUBKEY)?;
    let kex_pubkey = c.take(LEN_PUBKEY)?;
    let not_before = c.u64be()?;
    let not_after = c.u64be()?;
    let name = c.field16(MAX_NAME)?;
    let scope_count = c.u8r()?;
    if scope_count > MAX_SCOPE {
        return Err(ParseError::Oversize);
    }
    let scope_ids = c.take(scope_count as usize * LEN_SCOPE_ID)?;
    let tbs = &buf[0..c.pos];
    let ca_sig_count = c.u8r()?;
    if ca_sig_count == 0 {
        return Err(ParseError::Malformed);
    }
    if ca_sig_count > MAX_CA_SIGS {
        return Err(ParseError::Oversize);
    }
    let ca_start = c.pos;
    let mut prev_key: &[u8] = &[];
    for i in 0..ca_sig_count {
        let ca_key = c.take(LEN_CA_KEY)?;
        if i > 0 && ca_key <= prev_key {
            return Err(ParseError::Malformed);
        }
        prev_key = ca_key;
        c.take(LEN_SIG)?;
    }
    let ca_sigs = &buf[ca_start..c.pos];
    if !c.rest().is_empty() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Cert {
        version,
        role_bits,
        sig_pubkey,
        kex_pubkey,
        not_before,
        not_after,
        name,
        scope_count,
        scope_ids,
        ca_sig_count,
        ca_sigs,
        tbs,
    })
}

// --- verification (BE-SIG-01: Ed25519 over domain_tag || tbs) ----------------
//
// NOTE: this path performs ONE small allocation to join tag||tbs (dalek
// verifies a single message slice). The PARSERS above stay zero-alloc — that
// is what BE-WIRE-01 pins. Revisit with a streaming verifier only if a gate
// ever demands it.

/// Verify `sig` over `domain_tag || tbs` with `signer`. Returns false on any
/// failure (bad key, bad sig, wrong tag) — never panics.
pub fn verify_signed(domain_tag: u8, tbs: &[u8], sig: &[u8], signer: &[u8]) -> bool {
    let Ok(key_bytes) = <&[u8; 32]>::try_from(signer) else {
        return false;
    };
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(key_bytes), Signature::from_slice(sig)) else {
        return false;
    };
    let mut input = Vec::with_capacity(1 + tbs.len());
    input.push(domain_tag);
    input.extend_from_slice(tbs);
    key.verify(&input, &sig).is_ok()
}

// --- canonical re-encoding (round-trip oracle for the conformance tests) ----
//
// Encoders allocate (they BUILD); parsers never do. Field order is the
// grammar above; re-encode(parse(w)) MUST equal w byte-for-byte.

fn push_field16(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
}

fn push_field32(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
    out.extend_from_slice(v);
}

pub fn encode_envelope(e: &Envelope<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_HEADER);
    out.push(e.version);
    out.extend_from_slice(e.channel_id);
    out.extend_from_slice(e.sender);
    out.extend_from_slice(&e.seq.to_be_bytes());
    out.push(e.parent_count);
    out.extend_from_slice(e.parents);
    out.extend_from_slice(&e.ts.to_be_bytes());
    out.push(e.body_type);
    out.extend_from_slice(&(e.body.len() as u32).to_be_bytes());
    out.extend_from_slice(e.body);
    out.extend_from_slice(e.sig);
    out
}

pub fn encode_intent(i: &Intent<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(i.intent_id);
    push_field16(&mut out, i.resource_id);
    push_field32(&mut out, i.action);
    push_field16(&mut out, i.rationale);
    out
}

pub fn encode_grant(g: &Grant<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(g.version);
    out.extend_from_slice(g.grant_id);
    out.extend_from_slice(g.intent_id);
    out.extend_from_slice(g.approver);
    out.extend_from_slice(g.subject);
    out.extend_from_slice(g.executor);
    push_field16(&mut out, g.resource_id);
    out.extend_from_slice(g.action_digest);
    out.extend_from_slice(&g.not_after.to_be_bytes());
    out.extend_from_slice(g.sig);
    out
}

pub fn encode_refusal(r: &Refusal<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(r.intent_id);
    push_field16(&mut out, r.note);
    out.extend_from_slice(r.sig);
    out
}

pub fn encode_span(s: &Span<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(s.version);
    out.extend_from_slice(s.span_id);
    out.extend_from_slice(s.trace_id);
    push_field16(&mut out, s.resource_id);
    out.push(s.method_id);
    out.push(s.volatility);
    out.extend_from_slice(s.origin);
    out.extend_from_slice(&s.observed_at.to_be_bytes());
    out.extend_from_slice(s.digest);
    out.extend_from_slice(s.executor);
    out.extend_from_slice(s.sig);
    out
}

pub fn encode_cert(c: &Cert<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(c.version);
    out.push(c.role_bits);
    out.extend_from_slice(c.sig_pubkey);
    out.extend_from_slice(c.kex_pubkey);
    out.extend_from_slice(&c.not_before.to_be_bytes());
    out.extend_from_slice(&c.not_after.to_be_bytes());
    push_field16(&mut out, c.name);
    out.push(c.scope_count);
    out.extend_from_slice(c.scope_ids);
    out.push(c.ca_sig_count);
    out.extend_from_slice(c.ca_sigs);
    out
}
