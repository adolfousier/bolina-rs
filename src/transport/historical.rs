//! W8 historical: no-clock audit path (historical.zig port).
//!
//! BE-HIST-01: no clock checks on committed signatures. A committed signature
//! stays valid after its cert expires; a cert whose chain was never sound was
//! never valid at any time.
//!
//! BE-HIST-03: envelope must be causal descendant of anchor and NOT descendant
//! of revocation.
//!
//! BE-HIST-04: revocation is immediate for admission, causal-positioned for audit.

use crate::transport::dag::{Dag, Node};

// ---------------------------------------------------------------------------
// Historical audit errors (BE-HIST-03).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalError {
    NotDescendantOfAnchor,
    DescendantOfRevocation,
    AnchorNotFound,
    // BE-HIST-01: cert chain errors surfaced through audit path.
    // CertExpired carried for set completeness only: the no-clock chain
    // takes no time input, so this path cannot emit it.
    MalformedKey,
    BadCaSignature,
    UntrustedCa,
    CertExpired,
    CertTooLongLived,
    RoleAgentApprover,
    RoleAgentExecutor,
    RoleApproverExecutor,
    ApproverNoQuorum,
}

// ---------------------------------------------------------------------------
// Audit context: every input needed for historical validity checks.
// ---------------------------------------------------------------------------

pub struct AuditContext<'a> {
    /// Lookup anchor hash for a sender pubkey.
    pub get_anchor: &'a dyn Fn(&[u8; 32]) -> Option<Node>,
    /// Lookup revoke envelope hash for a sender pubkey.
    pub get_revoke_hash: &'a dyn Fn(&[u8; 32]) -> Option<Node>,
    /// Validate cert structurally without clock (BE-HIST-01).
    pub validate_cert_no_clock: &'a dyn Fn(&[u8]) -> Result<(), HistoricalError>,
    pub dag: &'a mut Dag,
}

// ---------------------------------------------------------------------------
// Historical validity check (BE-HIST-01/03/04).
//
// Returns error if the envelope was not valid at the time of commitment.
// ---------------------------------------------------------------------------

pub fn historical_validity(
    env_hash: &Node,
    sender: &[u8; 32],
    sender_cert: &[u8],
    ctx: &mut AuditContext<'_>,
) -> Result<(), HistoricalError> {
    // BE-HIST-01: sender's cert revalidated structurally, no clock.
    (ctx.validate_cert_no_clock)(sender_cert)?;

    // BE-HIST-03: envelope must be causal descendant of anchor.
    let anchor_hash = (ctx.get_anchor)(sender).ok_or(HistoricalError::AnchorNotFound)?;
    if !ctx.dag.is_ancestor(&anchor_hash, env_hash) {
        return Err(HistoricalError::NotDescendantOfAnchor);
    }

    // BE-HIST-04 causal form: envelope committed before revocation stays
    // historically valid; only descendant of revocation fails.
    if let Some(revoke_hash) = (ctx.get_revoke_hash)(sender) {
        if ctx.dag.is_ancestor(&revoke_hash, env_hash) {
            return Err(HistoricalError::DescendantOfRevocation);
        }
    }

    Ok(())
}
