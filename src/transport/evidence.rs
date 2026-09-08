//! W8 evidence: attestation verdict layer (evidence.zig port).
//!
//! BE-EVID-02: the RECEIVER decides, by recomputing. A claim's confidence is
//! never the sender's number. It is min(stated, ceiling(strongest matching
//! supporting span)), and the ceiling is a pure function of HOW the span was
//! observed (method_id), never a field the producer chose.
//!
//! BE-EVID-09 forces three states: Supported (a number), Unresolved (no number,
//! pending backfill), Unsupported (0.00 with a marker).
//!
//! Pure and zero-heap: resolve_claim borrows the caller's parsed slices and
//! returns a value, allocating nothing.

use crate::codec::{verify_signed, DOMAIN_SPAN, LEN_SPAN_REF};

// ---------------------------------------------------------------------------
// Evidence class: derived, never declared (SPEC 7.4, BE-EVID-11/12/15).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClass {
    DirectObservation, // method_id 1..4, ceiling 242
    ExpertTestimony,   // method_id 7, ceiling 216
    Documentation,     // method_id 5..6, ceiling 191
    Inference,         // method_id 8 and unknown, ceiling 165
}

pub fn class_of(method_id: u8) -> EvidenceClass {
    match method_id {
        1..=4 => EvidenceClass::DirectObservation,
        5 | 6 => EvidenceClass::Documentation,
        7 => EvidenceClass::ExpertTestimony,
        8 => EvidenceClass::Inference,
        _ => EvidenceClass::Inference, // BE-EVID-13: unknown -> floor
    }
}

/// Normative ceilings (SPEC 7.2). Integers only; floats are FORBIDDEN (BE-EVID-15).
pub fn ceiling_q8(class: EvidenceClass) -> u8 {
    match class {
        EvidenceClass::DirectObservation => 242,
        EvidenceClass::ExpertTestimony => 216,
        EvidenceClass::Documentation => 191,
        EvidenceClass::Inference => 165,
    }
}

// ---------------------------------------------------------------------------
// Volatility (BE-EVID-06): only value 2 means stable; everything else volatile.
// ---------------------------------------------------------------------------

pub fn is_volatile(volatility: u8) -> bool {
    volatility != 2
}

// ---------------------------------------------------------------------------
// BE-EVID-02: receiver recomputes from the strongest support.
// ---------------------------------------------------------------------------

pub fn effective_confidence(stated_q8: u8, strongest_ceiling_q8: u8) -> u8 {
    stated_q8.min(strongest_ceiling_q8)
}

// ---------------------------------------------------------------------------
// BE-EVID-10: bounded piggyback (SPEC 7.5).
// ---------------------------------------------------------------------------

pub const MAX_UTTERANCE_CLAIMS: usize = 32;
pub const MAX_UTTERANCE_SPANS: usize = 64;

pub fn check_bounds(claim_count: usize, span_count: usize) -> bool {
    claim_count <= MAX_UTTERANCE_CLAIMS && span_count <= MAX_UTTERANCE_SPANS
}

// ---------------------------------------------------------------------------
// Hooks: three facts that depend on state this slice does not model.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    None,
    Executor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginState {
    Effect,
    Absent,
    NonEffect,
}

pub struct ResolveContext<'a> {
    pub role_of: &'a dyn Fn(&[u8]) -> Role,
    pub resolve_origin: &'a dyn Fn(&[u8]) -> OriginState,
    pub is_superseded: &'a dyn Fn(&[u8], &[u8], &[u8]) -> bool,
}

// ---------------------------------------------------------------------------
// BE-EVID-09: three states, not two.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct ResolutionRecord {
    pub cited: usize,
    pub inline_spans: usize,
    pub supportable: usize,
    pub subject_matched: usize,
    pub superseded: usize,
    pub unresolved: usize,
    pub non_effect: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Supported {
    pub effective_q8: u8,
    pub pending_stronger: bool,
    pub record: ResolutionRecord,
}

#[derive(Debug, Clone, Copy)]
pub enum ClaimState {
    Supported(Supported),
    Unresolved(ResolutionRecord),
    Unsupported(ResolutionRecord),
}

// ---------------------------------------------------------------------------
// Span and Claim: lightweight parsed views for the resolve walk.
// ---------------------------------------------------------------------------

pub struct Span<'a> {
    pub span_id: &'a [u8],
    pub tbs: &'a [u8],
    pub sig: &'a [u8],
    pub executor: &'a [u8],
    pub resource_id: &'a [u8],
    pub origin: &'a [u8],
    pub volatility: u8,
    pub method_id: u8,
}

pub struct Claim<'a> {
    pub span_ids: &'a [u8], // packed span references
    pub span_count: usize,
    pub subject: &'a [u8],
    pub confidence_q8: u8,
}

// ---------------------------------------------------------------------------
// resolveClaim: the receiver's recomputation for one claim.
// ---------------------------------------------------------------------------

fn match_span<'a>(spans: &'a [Span<'a>], span_id: &[u8]) -> Option<&'a Span<'a>> {
    spans.iter().find(|s| s.span_id == span_id)
}

fn span_supportable(span: &Span<'_>, ctx: &ResolveContext<'_>) -> bool {
    // BE-EVID-01 conjunct 1: sig verifies against executor
    if !verify_signed(DOMAIN_SPAN, span.tbs, span.sig, span.executor) {
        return false;
    }
    // BE-EVID-01 conjunct 2: cert carries executor role
    (ctx.role_of)(span.executor) == Role::Executor
}

pub fn resolve_claim(
    claim: &Claim<'_>,
    spans: &[Span<'_>],
    ctx: &ResolveContext<'_>,
    claim_envelope: &[u8],
) -> ClaimState {
    let mut rec = ResolutionRecord::default();
    let mut strongest_ceiling: u8 = 0;
    let mut has_unresolved = false;

    for i in 0..claim.span_count {
        rec.cited += 1;
        let start = i * LEN_SPAN_REF;
        let end = start + LEN_SPAN_REF;
        if end > claim.span_ids.len() {
            break;
        }
        let sid = &claim.span_ids[start..end];

        let span = match match_span(spans, sid) {
            Some(s) => s,
            None => continue, // BE-EVID-08: cited but not inline
        };
        rec.inline_spans += 1;

        if !span_supportable(span, ctx) {
            continue; // BE-EVID-01 fail
        }
        rec.supportable += 1;

        if span.resource_id != claim.subject {
            continue; // BE-EVID-03 fail
        }
        rec.subject_matched += 1;

        match (ctx.resolve_origin)(span.origin) {
            OriginState::Effect => {
                // BE-EVID-05: only volatile spans can be superseded
                if is_volatile(span.volatility)
                    && (ctx.is_superseded)(span.resource_id, span.origin, claim_envelope)
                {
                    rec.superseded += 1;
                    continue;
                }
                let ceil = ceiling_q8(class_of(span.method_id));
                if ceil > strongest_ceiling {
                    strongest_ceiling = ceil;
                }
            }
            OriginState::Absent => {
                rec.unresolved += 1;
                has_unresolved = true;
            }
            OriginState::NonEffect => {
                rec.non_effect += 1;
                continue;
            }
        }
    }

    if strongest_ceiling > 0 {
        ClaimState::Supported(Supported {
            effective_q8: effective_confidence(claim.confidence_q8, strongest_ceiling),
            pending_stronger: has_unresolved,
            record: rec,
        })
    } else if has_unresolved {
        ClaimState::Unresolved(rec)
    } else {
        ClaimState::Unsupported(rec)
    }
}
