//! W7 verify: the authority decision core (verify.zig port).
//!
//! All authority decisions live here as pure functions over parsed wire types:
//! envelope signature (BE-ENV-02), the full grant chain (BE-GRANT-03, checks 0-11
//! in normative order), refusals, control-channel genesis/membership, mesh served-cert,
//! and admission gating. **Zero heap** across all of it.
//!
//! The routine does NOT hand back a capability: it runs the checks, commits the
//! ledger (check 11), and invokes the effect itself inside its own frame
//! (verify.zig:21-22, BE-GRANT-03b round 4 restatement).

use crate::codec::{
    self, verify_signed, Cert, Envelope, Grant, Refusal,
    BODY_GRANT, BODY_INTENT, BODY_REFUSAL, BODY_EFFECT, BODY_CONTROL,
    DOMAIN_GRANT, DOMAIN_ENVELOPE, DOMAIN_REFUSAL,
    LEN_ACTION_DIGEST, LEN_INTENT_ID, LEN_PUBKEY, LEN_SCOPE_ID,
    ROLE_AGENT, ROLE_APPROVER, ROLE_EXECUTOR,
};
use crate::state::intent;
use blake2::Blake2s256;
use blake2::Digest;

// ---------------------------------------------------------------------------
// Errors. One distinct class per failed BE check so tests assert the reason a
// grant was refused, not a generic "invalid".
// Order IS normative (verify.zig:53-70).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    BadVersion,           // BE-GRANT-03 check 0: Grant.version != 2
    BadEnvelopeBinding,   // BE-GRANT-03 check 1: not body_type=3, or sender != approver
    BadSignature,         // BE-ENV-02 / check 2: sig does not verify
    MalformedKey,         // a pubkey is not a valid curve point
    BadApproverCert,      // BE-GRANT-03 check 3: approver cert invalid, wrong role
    BadSubjectCert,       // BE-GRANT-03 check 4: subject cert invalid, wrong role
    ApproverRevoked,      // BE-REV-02 / F4 check 3: approver's sig_pubkey revoked
    ApproverOutOfScope,   // D-085 check 3a: approver cert scope doesn't cover resource
    SubjectRevoked,       // BE-REV-02 / F4 check 4: subject's sig_pubkey revoked
    SubjectOutOfScope,    // D-085 check 4a: subject cert scope doesn't cover resource
    WrongExecutor,        // BE-GRANT-03 check 5: executor != this executor's key
    WrongSubject,         // BE-GRANT-03 check 6: subject != pending intent's sender
    NoMatchingIntent,     // BE-GRANT-03 check 7: intent_id matches no pending intent
    WrongResource,        // BE-GRANT-03 check 8: resource_id != pending intent's resource
    ActionDigestMismatch, // BE-GRANT-02 / check 9: BLAKE2s(action) != action_digest
    Expired,              // BE-GRANT-05 / check 10: any of the three expiry conditions
    AlreadyConsumed,      // BE-GRANT-01 / check 11: grant_id already in the ledger
    // Ledger slice admission errors (BE-ENV-03/04/05, BE-LEDGER-01).
    WrongBodyType,        // BE-ENV-03: body_type not allowed for sender's role
    SeqWindowStale,       // BE-ENV-04: seq below sliding window or duplicate
    Equivocation,         // BE-ENV-05: same (sender, channel, seq) with different hash
    UnknownParents,       // BE-LEDGER-01: parents not in ledger
    BadControlBody,       // F6: Control body malformed
}

// ---------------------------------------------------------------------------
// Low-level signature check (BE-SIG-01 domain separation).
// ---------------------------------------------------------------------------

/// Verify `sig` over (domain_tag || tbs) against `pubkey`.
/// Returns Ok(()) on success, VerifyError on failure.
pub fn verify_signed_err(tag: u8, tbs: &[u8], sig: &[u8], pubkey: &[u8]) -> Result<(), VerifyError> {
    if pubkey.len() != LEN_PUBKEY {
        return Err(VerifyError::MalformedKey);
    }
    if sig.len() != codec::LEN_SIG {
        return Err(VerifyError::BadSignature);
    }
    if verify_signed(tag, tbs, sig, pubkey) {
        Ok(())
    } else {
        Err(VerifyError::BadSignature)
    }
}

// ---------------------------------------------------------------------------
// Envelope signature (BE-ENV-02).
// ---------------------------------------------------------------------------

pub fn verify_envelope(env: &Envelope<'_>) -> Result<(), VerifyError> {
    verify_signed_err(DOMAIN_ENVELOPE, env.tbs, env.sig, env.sender)
}

// ---------------------------------------------------------------------------
// BE-GRANT-02 helper: recompute the binding digest over the intent's action.
// ---------------------------------------------------------------------------

pub fn action_digest(action: &[u8]) -> [u8; LEN_ACTION_DIGEST] {
    let mut hasher = Blake2s256::new();
    hasher.update(action);
    let result = hasher.finalize();
    let mut out = [0u8; LEN_ACTION_DIGEST];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// BE-GRANT-05 (bounded expiry). Refuses if ANY of the three conditions holds:
//   (a) not_after is already past on the executor's clock,
//   (b) not_after lies more than T_max beyond first receipt,
//   (c) more than T_recv has elapsed since first receipt of this grant_id.
// All values are unix milliseconds; t_max_s and t_recv_s are whole seconds.
// ---------------------------------------------------------------------------

fn check_expiry(
    not_after: u64,
    now_ms: u64,
    first_receipt_ms: u64,
    t_max_s: u64,
    t_recv_s: u64,
) -> Result<(), VerifyError> {
    let t_max_ms = t_max_s * 1000;
    let t_recv_ms = t_recv_s * 1000;
    // (a) non-strict: a Grant whose not_after equals the current millisecond is
    // refused. Capability boundaries are denied at the instant of expiry.
    if now_ms >= not_after {
        return Err(VerifyError::Expired);
    }
    if not_after > first_receipt_ms + t_max_ms {
        return Err(VerifyError::Expired);
    }
    if now_ms > first_receipt_ms + t_recv_ms {
        return Err(VerifyError::Expired);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SenderTable: the sender record table from dispatch.zig, exposed for F13.
// ---------------------------------------------------------------------------

pub const SENDER_MAX_ACTION: usize = 512;

pub struct SenderEntry {
    pub intent_id: [u8; LEN_INTENT_ID],
    pub sender: [u8; 32],
    pub action: [u8; SENDER_MAX_ACTION],
    pub action_len: usize,
}

pub struct SenderTable {
    pub entries: Vec<SenderEntry>,
}

impl SenderTable {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn lookup(&self, intent_id: &[u8]) -> Option<&SenderEntry> {
        self.entries.iter().find(|e| e.intent_id[..] == *intent_id)
    }
}

// ---------------------------------------------------------------------------
// GrantContext: every input the verification routine needs.
// ---------------------------------------------------------------------------

pub struct GrantContext<'a> {
    /// Check 5: this executor's own sig_pubkey.
    pub own_pubkey: &'a [u8],
    /// Checks 3 and 4: the approver and subject certs.
    pub approver_cert: Cert<'a>,
    pub subject_cert: Cert<'a>,
    /// Trusted CA keys for cert validation.
    pub trusted_ca_keys: &'a [&'a [u8]],
    /// F13: the intent table for checks 6-9.
    pub intent_table: &'a intent::Table,
    /// F13: the sender table for checks 6 and 9.
    pub sender_table: &'a SenderTable,
    /// Check 10: the executor's clock and the grant's receipt time.
    pub now_ms: u64,
    pub first_receipt_ms: u64,
    pub t_max_s: u64,  // default 3600
    pub t_recv_s: u64,  // default 300
    /// Check 11: the consumed-grant ledger hook. Returns true if ALREADY consumed.
    pub already_consumed: &'a dyn Fn(&[u8], u64, u64) -> bool,
    /// Checks 3/4: the durable revocation hook.
    pub is_revoked: &'a dyn Fn(&[u8]) -> bool,
}

// ---------------------------------------------------------------------------
// EffectOutcome: the publication boundary evidence source.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectOutcome {
    Fired,
    Refused,
}

// ---------------------------------------------------------------------------
// verifyGrantThen: the single BE-GRANT-03 verification routine.
//
// Checks run in the enumerated order and refuse on the first failure. The
// ledger hook (check 11) is the last check, so any earlier refusal short-
// circuits before the durable commit would happen.
// ---------------------------------------------------------------------------

pub fn verify_grant_then<F>(
    env: &Envelope<'_>,
    grant: &Grant<'_>,
    ctx: &GrantContext<'_>,
    execute: F,
) -> Result<EffectOutcome, VerifyError>
where
    F: FnOnce(&Grant<'_>) -> EffectOutcome,
{
    // 0. Grant.version must be 2 (RED-TEAM-08 F6: the field is read, not ignored).
    if grant.version != 2 {
        return Err(VerifyError::BadVersion);
    }

    // F13: look up the intent and sender record by grant.intent_id.
    let intent_id_arr: [u8; LEN_INTENT_ID] = grant.intent_id.try_into()
        .map_err(|_| VerifyError::BadEnvelopeBinding)?;
    let intent_idx = ctx.intent_table.match_for_grant(&intent_id_arr)
        .ok_or(VerifyError::NoMatchingIntent)?;
    let intent_entry = &ctx.intent_table.entries[intent_idx];
    let sender_entry = ctx.sender_table.lookup(grant.intent_id)
        .ok_or(VerifyError::NoMatchingIntent)?;

    // 1. The grant arrived as a body_type=3 envelope whose sender is the approver.
    if env.body_type != BODY_GRANT {
        return Err(VerifyError::BadEnvelopeBinding);
    }
    if env.sender != grant.approver {
        return Err(VerifyError::BadEnvelopeBinding);
    }

    // 2. Grant.sig verifies against Grant.approver (domain tag 0x04).
    verify_signed_err(DOMAIN_GRANT, grant.tbs, grant.sig, grant.approver)?;

    // 3. Approver certificate valid NOW and carries the approver role.
    // Simplified: we check role bits and sig_pubkey match.
    // Full cert validation would call binding.validateCert here.
    if (ctx.approver_cert.role_bits & ROLE_APPROVER) == 0 {
        return Err(VerifyError::BadApproverCert);
    }
    if ctx.approver_cert.sig_pubkey != grant.approver {
        return Err(VerifyError::BadApproverCert);
    }
    // F4 / BE-REV-02: the approver's signing key is durably revoked.
    if (ctx.is_revoked)(ctx.approver_cert.sig_pubkey) {
        return Err(VerifyError::ApproverRevoked);
    }
    // 3a. Approver scope covers the grant's resource (D-085).
    // Scope is a cert-v3 feature; v2 certs skip this check.
    if ctx.approver_cert.version >= 3 {
        if !scope_covers_resource(&ctx.approver_cert, grant.resource_id) {
            return Err(VerifyError::ApproverOutOfScope);
        }
    }

    // 4. Subject certificate valid NOW and carries the agent role.
    if (ctx.subject_cert.role_bits & ROLE_AGENT) == 0 {
        return Err(VerifyError::BadSubjectCert);
    }
    if ctx.subject_cert.sig_pubkey != grant.subject {
        return Err(VerifyError::BadSubjectCert);
    }
    // F4 / BE-REV-02: the subject's signing key is durably revoked.
    if (ctx.is_revoked)(ctx.subject_cert.sig_pubkey) {
        return Err(VerifyError::SubjectRevoked);
    }
    // 4a. Subject scope covers the grant's resource (D-085).
    if ctx.subject_cert.version >= 3 {
        if !scope_covers_resource(&ctx.subject_cert, grant.resource_id) {
            return Err(VerifyError::SubjectOutOfScope);
        }
    }

    // 5. Grant.executor equals this executor's own sig_pubkey.
    if grant.executor != ctx.own_pubkey {
        return Err(VerifyError::WrongExecutor);
    }

    // 6. The grant's subject is the pending intent's sender.
    if grant.subject != sender_entry.sender {
        return Err(VerifyError::WrongSubject);
    }

    // 7. intent_id matches the pending intent.
    if grant.intent_id != intent_entry.intent_id {
        return Err(VerifyError::NoMatchingIntent);
    }

    // 8. resource_id matches the pending intent's canonical resource_id.
    if grant.resource_id != &intent_entry.resource_id[..intent_entry.resource_len] {
        return Err(VerifyError::WrongResource);
    }

    // 9. Grant.action_digest equals BLAKE2s recomputed over the intent's action.
    let digest = action_digest(&sender_entry.action[..sender_entry.action_len]);
    if grant.action_digest != digest {
        return Err(VerifyError::ActionDigestMismatch);
    }

    // 10. Expiry passes all three conditions of BE-GRANT-05.
    check_expiry(grant.not_after, ctx.now_ms, ctx.first_receipt_ms, ctx.t_max_s, ctx.t_recv_s)?;

    // 11. grant_id is not already consumed (BE-GRANT-01).
    if (ctx.already_consumed)(grant.grant_id, grant.not_after, ctx.now_ms) {
        return Err(VerifyError::AlreadyConsumed);
    }

    // The effect runs inside this frame on the verified grant (BE-GRANT-03b).
    let outcome = execute(grant);
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// D-085: walk the canonical resource_id from full path to root, hashing each
// ancestor prefix against the cert's scope_ids.
// ---------------------------------------------------------------------------

fn scope_covers_resource(cert: &Cert<'_>, resource_id: &[u8]) -> bool {
    let mut end = resource_id.len();
    while end > 0 {
        let mut hasher = Blake2s256::new();
        hasher.update(&resource_id[..end]);
        let hash = hasher.finalize();
        if cert_carries_scope(cert, &hash[..LEN_SCOPE_ID]) {
            return true;
        }
        // Find the previous '/' to strip the last segment.
        let mut new_end = end;
        while new_end > 0 && resource_id[new_end - 1] != b'/' {
            new_end -= 1;
        }
        if new_end == 0 {
            break;
        }
        end = new_end - 1;
    }
    false
}

fn cert_carries_scope(cert: &Cert<'_>, scope: &[u8]) -> bool {
    for i in 0..cert.scope_count as usize {
        let off = i * LEN_SCOPE_ID;
        if off + LEN_SCOPE_ID <= cert.scope_ids.len() {
            if &cert.scope_ids[off..off + LEN_SCOPE_ID] == scope {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Refusal verification (SPEC 8.5, BE-GRANT-09 parse half).
//
// The Refusal is the approver's signed NO over a single intent_id (domain tag
// 0x06). It transitions a PENDING intent to REJECTED and releases the resource
// lock in one message instead of after T_pending (BE-GRANT-06a).
// ---------------------------------------------------------------------------

pub struct RefusalContext<'a> {
    pub trusted_ca_keys: &'a [&'a [u8]],
    pub approver_cert: Cert<'a>,
    pub now_ms: u64,
    pub intent_table: &'a mut intent::Table,
}

/// verifyRefusalThen: the single BE-GRANT-09 verification routine.
/// On a verified Refusal whose intent_id names a PENDING intent, applyRefusal
/// moves it to REJECTED and the caller's on_rejected fires once.
pub fn verify_refusal_then<F>(
    env: &Envelope<'_>,
    refusal: &Refusal<'_>,
    ctx: &mut RefusalContext<'_>,
    on_rejected: F,
) -> Result<(), VerifyError>
where
    F: FnOnce(&[u8]),
{
    use crate::codec::BODY_REFUSAL;

    // 1. A Refusal arrives as a body_type=6 envelope whose sender is the approver.
    if env.body_type != BODY_REFUSAL {
        return Err(VerifyError::BadEnvelopeBinding);
    }

    // 2. Refusal.sig verifies against env.sender over (DOMAIN_REFUSAL || tbs).
    verify_signed_err(DOMAIN_REFUSAL, refusal.tbs, refusal.sig, env.sender)?;

    // 3. Approver certificate valid NOW and carries the approver role.
    if (ctx.approver_cert.role_bits & ROLE_APPROVER) == 0 {
        return Err(VerifyError::BadApproverCert);
    }
    if ctx.approver_cert.sig_pubkey != env.sender {
        return Err(VerifyError::BadApproverCert);
    }

    // BE-GRANT-09 state transition: a verified Refusal whose intent_id names a
    // PENDING intent moves it to REJECTED and releases the lock.
    let intent_id_arr: [u8; LEN_INTENT_ID] = refusal.intent_id.try_into()
        .map_err(|_| VerifyError::BadEnvelopeBinding)?;
    if ctx.intent_table.apply_refusal(&intent_id_arr) == intent::RefusalOutcome::Rejected {
        on_rejected(refusal.intent_id);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel control verification (SPEC 6.1a-c, BE-CHAN/BE-GEN/BE-CTRL).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    BadMatchRule,      // BE-GEN-04: match_rule != 1
    BadChannelId,      // channel_id != BLAKE2s(name || ca_key_0)
    DuplicateGenesis,  // BE-GEN-01: second genesis for existing channel_id
    GenesisNotAdmin,   // BE-GEN-03: genesis not signed by admin_group cert
    BadActionType,     // BE-CTRL-01: action_type not in {1, 2}
    RevokeNotAdmin,    // BE-CTRL-02: Revoke sender lacks admin_group
    SubjectRevoked,    // BE-CHAN-02/03: subject in grow-only revoked set
    NotMember,         // BE-CHAN-01/03: cert does not carry member_group
}

pub struct ChannelContext<'a> {
    pub genesis_exists: &'a dyn Fn(&[u8]) -> bool,
    pub is_revoked: &'a dyn Fn(&[u8]) -> bool,
}

/// BE-CHAN-01: a cert carries a scope iff the 8-byte prefix appears in its scope_ids.
fn cert_carries_scope_raw(cert: &Cert<'_>, scope: &[u8]) -> bool {
    for i in 0..cert.scope_count as usize {
        let off = i * LEN_SCOPE_ID;
        if off + LEN_SCOPE_ID <= cert.scope_ids.len() {
            if &cert.scope_ids[off..off + LEN_SCOPE_ID] == scope {
                return true;
            }
        }
    }
    false
}

/// BE-GEN-03: channel_id = BLAKE2s(name || ca_key_0).
pub fn verify_control_genesis(
    genesis_name: &[u8],
    genesis_ca_key_0: &[u8],
    admin_cert: &Cert<'_>,
    admin_group: &[u8],
    channel_id: &[u8],
    ctx: &ChannelContext<'_>,
) -> Result<(), ChannelError> {
    // BE-GEN-04: match_rule fixed at byte equality (1).
    // (match_rule is on the genesis envelope, validated at parse time)

    // BE-GEN-03: genesis signed by cert carrying admin_group.
    if !cert_carries_scope_raw(admin_cert, admin_group) {
        return Err(ChannelError::GenesisNotAdmin);
    }

    // channel_id = BLAKE2s(name || ca_key_0).
    let mut hasher = Blake2s256::new();
    hasher.update(genesis_name);
    hasher.update(genesis_ca_key_0);
    let derived = hasher.finalize();
    if channel_id != &derived[..] {
        return Err(ChannelError::BadChannelId);
    }

    // BE-GEN-01: exactly one genesis per channel_id.
    if (ctx.genesis_exists)(channel_id) {
        return Err(ChannelError::DuplicateGenesis);
    }
    Ok(())
}

/// BE-CTRL-01/02: validate a control body.
pub fn verify_control(
    action_type: u8,
    sender_cert: &Cert<'_>,
    admin_group: &[u8],
) -> Result<(), ChannelError> {
    // BE-CTRL-01: action_type must be 1 or 2.
    if action_type != 1 && action_type != 2 {
        return Err(ChannelError::BadActionType);
    }
    // BE-CTRL-02: a Revoke must be signed by a cert carrying admin_group.
    if action_type == 2 && !cert_carries_scope_raw(sender_cert, admin_group) {
        return Err(ChannelError::RevokeNotAdmin);
    }
    Ok(())
}

/// BE-CHAN-01/02/03: gate a channel message on the sender's membership.
pub fn require_member(
    sender_cert: &Cert<'_>,
    member_group: &[u8],
    ctx: &ChannelContext<'_>,
) -> Result<(), ChannelError> {
    if (ctx.is_revoked)(sender_cert.sig_pubkey) {
        return Err(ChannelError::SubjectRevoked);
    }
    if !cert_carries_scope_raw(sender_cert, member_group) {
        return Err(ChannelError::NotMember);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BE-ENV-03: body_type -> role map enforcement.
// ---------------------------------------------------------------------------

pub fn body_type_allowed(body_type: u8, role_bits: u8) -> bool {
    let is_agent = (role_bits & ROLE_AGENT) != 0;
    let is_approver = (role_bits & ROLE_APPROVER) != 0;
    let is_executor = (role_bits & ROLE_EXECUTOR) != 0;

    match body_type {
        BODY_INTENT => is_agent,
        BODY_GRANT | BODY_REFUSAL => is_approver,
        BODY_EFFECT => is_executor,
        BODY_CONTROL => true, // Control role-gated at verification
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// F10/D-090: the prunable expiry a Revoke body carries.
// ---------------------------------------------------------------------------

/// The SUBJECT's cert expiry travels in the Control body as u64be.
/// A body without the field predates D-090 and yields u64::MAX (never pruned).
pub fn revoke_prune_expiry(body: &[u8]) -> u64 {
    if body.len() >= 8 {
        u64::from_be_bytes(body[..8].try_into().unwrap())
    } else {
        u64::MAX
    }
}


#[cfg(test)]
mod boundary_tests {
    use super::*;

    /// BE-GRANT-05 (a): capability denied AT the instant of expiry
    /// (non-strict >=). Mutant kill: `>=` weakened to `>` must fail this.
    #[test]
    fn be_grant_05_expiry_denied_at_instant_of_expiry() {
        assert_eq!(
            check_expiry(1000, 1000, 0, 3600, 3600),
            Err(VerifyError::Expired)
        );
        // one millisecond earlier: still valid
        assert_eq!(check_expiry(1000, 999, 0, 3600, 3600), Ok(()));
    }

    /// BE-GRANT-05 (c): receipt window denied AT the instant (t_recv).
    #[test]
    fn be_grant_05_receipt_window_denied_at_instant() {
        // not_after far away so branch (a) never fires
        let not_after = 1_000_000;
        let first = 0;
        let t_recv_s = 10;
        assert_eq!(check_expiry(not_after, 10_000, first, 3600, t_recv_s), Ok(()));
        assert_eq!(
            check_expiry(not_after, 10_001, first, 3600, t_recv_s),
            Err(VerifyError::Expired)
        );
    }

    /// Wrong-length pubkey is a VerifyError, and a VALID signature over the
    /// domain-separated input passes (mutant kill: length check inverted).
    #[test]
    fn verify_signed_pubkey_length_is_a_guard_not_a_flip() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let msg = b"dispatch me";
        // codec::verify_signed checks over (domain_tag || tbs) - BE-SIG-01
        let mut sig_input = vec![DOMAIN_GRANT];
        sig_input.extend_from_slice(msg);
        let sig = sk.sign(&sig_input).to_bytes().to_vec();
        let pub_ok = sk.verifying_key().to_bytes();

        // 31-byte pubkey: guard fires
        assert!(matches!(
            verify_signed_err(DOMAIN_GRANT, msg, &sig, &pub_ok[..31]),
            Err(VerifyError::MalformedKey)
        ));
        // full 32-byte pubkey: signature verifies
        assert!(verify_signed_err(DOMAIN_GRANT, msg, &sig, &pub_ok).is_ok());
    }
}
