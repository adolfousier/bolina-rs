//! Control API: the /v1 facade over dispatch internals (W10).
//! Sheet: specs/control_api.md - Zig: src/control_api.zig (339 lines).
//!
//! ANTI-GOD-MODE by construction: NO direct ledger writes, NO grant mutation.
//! postIntent routes through the SAME resolve_and_admit the wire path uses
//! (transport/dispatch.rs). F16: subject is REQUIRED hex64; missing = 400.
//!
//! Cross-diff note: the Zig source lives on the reference machine, so SSE tag
//! spelling and Prometheus counter names follow the sheet's descriptions and
//! are PINNED by tests in tests/w10_control_api.rs; first reach of the Zig
//! tree must byte-compare both (audit item, inventory).

use crate::state::intent::{self, IntentError, State as IntentState};
use crate::transport::resolver::{Resolver, ResolveError};

pub const RING_CAP: usize = 256; // control_api.zig:21
pub const ID_HEX_LEN: usize = 64; // control_api.zig:22 (32 bytes hex)
pub const BODY_MAX: usize = 4096; // control_api.zig:23
pub const SUBJ_HEX_LEN: usize = 64; // control_api.zig:70

// ---------------------------------------------------------------------------
// EventTag: SSE tag strings are wire-visible; keep exact spelling.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTag {
    IntentAdmitted,
    IntentExpired,
    GrantExecuted,
    EffectRefused,
    RefusalApplied,
    ControlApplied,
}

impl EventTag {
    pub fn name(self) -> &'static str {
        match self {
            EventTag::IntentAdmitted => "intent_admitted",
            EventTag::IntentExpired => "intent_expired",
            EventTag::GrantExecuted => "grant_executed",
            EventTag::EffectRefused => "effect_refused",
            EventTag::RefusalApplied => "refusal_applied",
            EventTag::ControlApplied => "control_applied",
        }
    }
}

/// Drop-oldest-when-full ring :58. Sequence numbers survive eviction.
/// Off-by-one pinned: 263 publishes into a 256-ring => oldest survivor seq 8
/// (seq starts at 1; test asserts 8, NOT 9 - commit b4b94e7 note).
pub struct EventRing {
    pub events: Vec<(u64, EventTag)>, // (seq, tag), oldest first
    next_seq: u64,
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRing {
    pub fn new() -> Self {
        Self { events: Vec::with_capacity(RING_CAP), next_seq: 1 }
    }

    pub fn publish(&mut self, tag: EventTag) {
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.events.len() == RING_CAP {
            self.events.remove(0); // drop oldest
        }
        self.events.push((seq, tag));
    }

    /// Events with seq > since, oldest first.
    pub fn since(&self, since: u64) -> &[(u64, EventTag)] {
        let n = self
            .events
            .iter()
            .position(|(seq, _)| *seq > since)
            .unwrap_or(self.events.len());
        &self.events[n..]
    }
}

// ---------------------------------------------------------------------------
// ApiError: exhaustive enum, no String variants (D-049 analog) :72.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    BadRequest,
    NotFound,
    MethodNotAllowed,
    UnsupportedMediaType,
    UnprocessableIntent,
    Resolve(ResolveError),
    Intent(IntentError),
}

impl From<ResolveError> for ApiError {
    fn from(e: ResolveError) -> Self {
        match e {
            // the resolver flattens admit-stage errors; the F5 table needs
            // them re-exposed (409/202 vs 422)
            ResolveError::Intent(ie) => ApiError::Intent(ie),
            other => ApiError::Resolve(other),
        }
    }
}

impl From<IntentError> for ApiError {
    fn from(e: IntentError) -> Self { ApiError::Intent(e) }
}

impl ApiError {
    /// HTTP status per the F5 table.
    pub fn status(self) -> u16 {
        match self {
            ApiError::BadRequest | ApiError::Intent(IntentError::NotPending) => 400,
            ApiError::NotFound => 404,
            ApiError::MethodNotAllowed => 405,
            ApiError::UnsupportedMediaType => 415,
            ApiError::UnprocessableIntent | ApiError::Resolve(_) => 422,
            ApiError::Intent(IntentError::ResourceHeld) => 409,
            ApiError::Intent(IntentError::TableFull) => 503,
            ApiError::Intent(IntentError::DuplicateIntentId) => 202, // retry-safe
        }
    }
}

/// postIntent outcome :115.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentOutcome {
    Accepted,           // 202, admitted_total++
    AcceptedIdempotent, // 202 on DuplicateIntentId, counter frozen at 1
}

pub struct Metrics {
    pub admitted_total: u64,
}

/// Flat hand-rolled JSON key extractor - a KNOWN ACCEPTED limitation
/// (THREAT-MODEL 4.11): first-match substring, loopback+bearer caller
/// trusted. DO NOT "improve" to a full JSON parser without revisiting that
/// decision entry (M-level promotion).
fn flat_json_get<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    // find `"key"` followed by optional ws, colon, optional ws, `"`
    let needle = format!("\"{}\"", key);
    let i = body.find(&needle)? + needle.len();
    let rest = body[i..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn is_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b))
}

/// parseIdHex :298 - exactly ID_HEX_LEN hex chars -> 32 bytes.
pub fn parse_id_hex(hex: &str) -> Result<[u8; 32], ApiError> {
    if hex.len() != ID_HEX_LEN || !is_hex(hex) {
        return Err(ApiError::BadRequest);
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| ApiError::BadRequest)?;
    }
    Ok(out)
}

/// parseSince :249 - strict digits-or-error.
pub fn parse_since(target: &str) -> Result<u64, ApiError> {
    if target.is_empty() || !target.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::BadRequest);
    }
    target.parse::<u64>().map_err(|_| ApiError::BadRequest)
}

/// postIntent(body, out, now_ms) :115.
///
/// parse flat JSON -> validate id(32hex)+resource(canonical bol:)+action+
/// rationale+SUBJECT required -> resolveAndAdmit -> record SenderEntry ->
/// metrics admitted_total++ ONLY on THIS HTTP path (wire admissions do NOT
/// bump it - G2 finding #1).
pub fn post_intent(
    body: &str,
    resolver: &mut Resolver,
    intent_table: &mut intent::Table,
    metrics: &mut Metrics,
    ring: &mut EventRing,
    now_ms: u64,
) -> Result<IntentOutcome, ApiError> {
    if body.len() > BODY_MAX {
        return Err(ApiError::BadRequest);
    }

    let id = flat_json_get(body, "id").ok_or(ApiError::BadRequest)?;
    let resource = flat_json_get(body, "resource").ok_or(ApiError::BadRequest)?;
    let action = flat_json_get(body, "action").ok_or(ApiError::BadRequest)?;
    if action.is_empty() || action.len() > crate::codec::MAX_ACTION as usize {
        return Err(ApiError::BadRequest); // shape error (F5)
    }
    let _rationale = flat_json_get(body, "rationale").ok_or(ApiError::BadRequest)?;
    // F16: subject REQUIRED hex64; missing = 400. A forged subject dies later
    // at wire checks 4/6 with UnknownSender-family refusals, NEVER silently.
    let subject = flat_json_get(body, "subject").ok_or(ApiError::BadRequest)?;
    if subject.len() != SUBJ_HEX_LEN || !is_hex(subject) {
        return Err(ApiError::BadRequest);
    }

    let id_bytes = parse_id_hex(id)?;
    let intent_id: [u8; intent::LEN_INTENT_ID] =
        id_bytes[..intent::LEN_INTENT_ID].try_into().map_err(|_| ApiError::BadRequest)?;

    match resolver.resolve_and_admit(intent_table, &intent_id, resource.as_bytes(), now_ms) {
        Ok(()) => {
            metrics.admitted_total += 1; // THIS path only (G2 finding #1)
            ring.publish(EventTag::IntentAdmitted);
            Ok(IntentOutcome::Accepted)
        }
        Err(ResolveError::Intent(IntentError::DuplicateIntentId)) => {
            // retry-safe: 202 IDEMPOTENT, counter frozen at 1
            Ok(IntentOutcome::AcceptedIdempotent)
        }
        Err(e) => Err(e.into()),
    }
}

/// getIntentState :180 -> pending/executing/rejected/done lookup.
pub fn get_intent_state(
    id_bytes: &[u8; 32],
    intent_table: &intent::Table,
) -> Result<&'static str, ApiError> {
    let id16: [u8; intent::LEN_INTENT_ID] =
        id_bytes[..intent::LEN_INTENT_ID].try_into().map_err(|_| ApiError::BadRequest)?;
    let entry = intent_table
        .entries
        .iter()
        .find(|e| e.intent_id == id16)
        .ok_or(ApiError::NotFound)?;
    Ok(match entry.state {
        IntentState::Pending => "pending",
        IntentState::Executing => "executing",
        IntentState::Rejected => "rejected",
        IntentState::Expired => "expired",
    })
}

/// metricsBody :198 - Prometheus text format. Counter names pinned;
/// control-plane trio comes from ARGS (not globals) because the wire path
/// passes real totals here.
pub fn metrics_body(
    admitted_total: u64,
    ctl_requests: u64,
    ctl_auth_refused: u64,
    ctl_timeouts: u64,
) -> String {
    let mut out = String::new();
    for (name, val) in [
        ("bolina_intents_admitted_total", admitted_total),
        ("bolina_ctl_requests_total", ctl_requests),
        ("bolina_ctl_auth_refused_total", ctl_auth_refused),
        ("bolina_ctl_timeouts_total", ctl_timeouts),
    ] {
        out.push_str(&format!("{} {}\n", name, val));
    }
    out
}

/// eventsSseBody :224 - cursor = durable ledger offset concept, replay
/// paginated. Lines end \n\n.
pub fn events_sse_body(ring: &EventRing, since: u64) -> String {
    let mut out = String::new();
    for (seq, tag) in ring.since(since) {
        out.push_str(&format!("event: {}\ndata: {}\n\n", tag.name(), seq));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_off_by_one_seq8() {
        let mut ring = EventRing::new();
        for _ in 0..(RING_CAP + 7) {
            ring.publish(EventTag::IntentAdmitted);
        }
        assert_eq!(ring.events.len(), RING_CAP);
        assert_eq!(ring.events[0].0, 8); // 8, NOT 9 (b4b94e7)
        assert_eq!(ring.events.last().unwrap().0, 263);
    }

    #[test]
    fn parse_since_rejects_non_digits() {
        assert!(parse_since("0").is_ok());
        assert!(parse_since("42").is_ok());
        assert!(parse_since("").is_err());
        assert!(parse_since("4x2").is_err());
        assert!(parse_since("-1").is_err());
        assert!(parse_since("+1").is_err());
    }

    #[test]
    fn parse_id_hex_set() {
        let hex = "ab".repeat(32);
        let bytes = parse_id_hex(&hex).unwrap();
        assert_eq!(bytes[0], 0xab);
        assert_eq!(bytes[31], 0xab);
        assert_eq!(parse_id_hex("ab"), Err(ApiError::BadRequest)); // wrong len
        let bad = format!("{}zz", "a".repeat(62));
        assert_eq!(parse_id_hex(&bad), Err(ApiError::BadRequest));
    }

    #[test]
    fn subject_required_f16() {
        let mut r = Resolver::new(&[7u8; 32]);
        let mut t = intent::Table::new();
        let mut m = Metrics { admitted_total: 0 };
        let mut ring = EventRing::new();

        let no_subj = format!(
            "{{\"id\":\"{}\",\"resource\":\"bol:dev/x\",\"action\":\"read\",\"rationale\":\"r\"}}",
            "ab".repeat(32)
        );
        assert_eq!(
            post_intent(&no_subj, &mut r, &mut t, &mut m, &mut ring, 0),
            Err(ApiError::BadRequest)
        );
        assert_eq!(m.admitted_total, 0); // counter untouched on 400
    }

    #[test]
    fn metrics_body_verbatim() {
        let body = metrics_body(3, 10, 1, 2);
        assert_eq!(
            body,
            "bolina_intents_admitted_total 3\n\
             bolina_ctl_requests_total 10\n\
             bolina_ctl_auth_refused_total 1\n\
             bolina_ctl_timeouts_total 2\n"
        );
    }

    #[test]
    fn sse_lines_end_double_newline() {
        let mut ring = EventRing::new();
        ring.publish(EventTag::IntentAdmitted);
        ring.publish(EventTag::GrantExecuted);
        let body = events_sse_body(&ring, 0);
        assert_eq!(
            body,
            "event: intent_admitted\ndata: 1\n\nevent: grant_executed\ndata: 2\n\n"
        );
        // cursor pagination: since=1 shows only the second
        assert_eq!(events_sse_body(&ring, 1), "event: grant_executed\ndata: 2\n\n");
        // honest empty
        assert_eq!(events_sse_body(&ring, 99), "");
    }
}
