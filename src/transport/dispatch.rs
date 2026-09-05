//! W7 dispatch: the router (dispatch.zig port).
//!
//! One envelope in -> ONE of seven outcomes out, with every state mutation
//! ordered exactly here: admission routes through resolveAndAdmit (same path
//! wire uses), grants execute through verifyGrantThen, durable consumed-grant
//! ledger owns replay refusal, effects fire EXACTLY ONCE inside the verify call.

use crate::codec::{
    parse_envelope, parse_grant, parse_intent, parse_refusal,
    Cert, Envelope, Grant,
    BODY_INTENT, BODY_GRANT, BODY_REFUSAL, BODY_UTTERANCE,
    BODY_EFFECT, BODY_CONTROL,
};
use crate::state::intent;
use crate::transport::verify::{
    verify_envelope, verify_grant_then, verify_refusal_then,
    GrantContext, RefusalContext, SenderTable, SenderEntry,
    EffectOutcome, VerifyError, SENDER_MAX_ACTION,
};
use crate::transport::resolver::{Resolver, ResolveError};

pub const T_MAX_S_DEFAULT: u64 = 3600;
pub const T_RECV_S_DEFAULT: u64 = 300;
pub const MAX_ACTION: usize = SENDER_MAX_ACTION;

// ---------------------------------------------------------------------------
// DispatchError: flat error enum at the dispatch boundary.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    BadEnvelope,
    BadBody,
    UnsupportedBody,
    NoPendingIntent,
    UnknownSender,
    ActionTooLarge,
    DiskError,
    Verify(VerifyError),
    Resolve(ResolveError),
}

impl From<VerifyError> for DispatchError {
    fn from(e: VerifyError) -> Self { DispatchError::Verify(e) }
}

impl From<ResolveError> for DispatchError {
    fn from(e: ResolveError) -> Self { DispatchError::Resolve(e) }
}

// ---------------------------------------------------------------------------
// Outcome: exhaustive, never collapse variants.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    IntentAdmitted,
    GrantExecuted,
    EffectRefused,   // unpublished orphan (BE-GRANT-01a)
    RefusalApplied,
    Utterance,
    Control,
    Effect,
}

// ---------------------------------------------------------------------------
// Hooks: caller-supplied function pointers (M10 shape).
// ---------------------------------------------------------------------------

pub struct Hooks<'a> {
    pub execute_effect: &'a dyn Fn(&Grant<'_>) -> EffectOutcome,
    pub cert_for_sender: &'a dyn Fn(&[u8]) -> Option<Cert<'a>>,
    pub on_rejected: &'a dyn Fn(&[u8]),
    pub is_revoked: &'a dyn Fn(&[u8]) -> bool,
    pub already_consumed: &'a dyn Fn(&[u8], u64, u64) -> bool,
}

// ---------------------------------------------------------------------------
// Dispatch: the router.
// ---------------------------------------------------------------------------

pub struct Dispatch<'a> {
    pub resolver: &'a Resolver,
    pub intent_table: &'a mut intent::Table,
    pub sender_table: &'a mut SenderTable,
    pub own_pubkey: &'a [u8],
    pub own_cert: Cert<'a>,
    pub trusted_ca_keys: &'a [&'a [u8]],
}

impl<'a> Dispatch<'a> {
    pub fn dispatch(
        &mut self,
        env_bytes: &[u8],
        hooks: &Hooks<'a>,
        now_ms: u64,
    ) -> Result<Outcome, DispatchError> {
        // 1. Parse envelope
        let env = parse_envelope(env_bytes).map_err(|_| DispatchError::BadEnvelope)?;

        // 2. Verify envelope signature (BE-ENV-02)
        verify_envelope(&env).map_err(DispatchError::Verify)?;

        // 3. Route by body_type
        match env.body_type {
            BODY_INTENT => self.dispatch_intent(&env, now_ms),
            BODY_GRANT => self.dispatch_grant(&env, hooks, now_ms),
            BODY_REFUSAL => self.dispatch_refusal(&env, hooks, now_ms),
            BODY_UTTERANCE => Ok(Outcome::Utterance),
            BODY_EFFECT => Ok(Outcome::Effect),
            BODY_CONTROL => Ok(Outcome::Control),
            _ => Err(DispatchError::UnsupportedBody),
        }
    }

    fn dispatch_intent(
        &mut self,
        env: &Envelope<'_>,
        now_ms: u64,
    ) -> Result<Outcome, DispatchError> {
        let intent = parse_intent(env.body).map_err(|_| DispatchError::BadBody)?;

        // Resolve resource to canonical form BEFORE admitting (BE-RES-01)
        let intent_id_arr: [u8; intent::LEN_INTENT_ID] = intent.intent_id.try_into()
            .map_err(|_| DispatchError::BadBody)?;

        self.resolver.resolve_and_admit(
            self.intent_table,
            &intent_id_arr,
            intent.resource_id,
            now_ms,
        )?;

        // Store sender record for later grant verification (F13)
        if intent.action.len() > MAX_ACTION {
            return Err(DispatchError::ActionTooLarge);
        }
        let mut action_buf = [0u8; SENDER_MAX_ACTION];
        action_buf[..intent.action.len()].copy_from_slice(intent.action);

        let mut sender_buf = [0u8; 32];
        if env.sender.len() == 32 {
            sender_buf.copy_from_slice(env.sender);
        }

        self.sender_table.entries.push(SenderEntry {
            intent_id: intent_id_arr,
            sender: sender_buf,
            action: action_buf,
            action_len: intent.action.len(),
        });

        Ok(Outcome::IntentAdmitted)
    }

    fn dispatch_grant(
        &mut self,
        env: &Envelope<'_>,
        hooks: &Hooks<'a>,
        now_ms: u64,
    ) -> Result<Outcome, DispatchError> {
        let grant = parse_grant(env.body).map_err(|_| DispatchError::BadBody)?;

        // Look up sender cert for cert chain validation
        let sender_cert = (hooks.cert_for_sender)(env.sender)
            .ok_or(DispatchError::UnknownSender)?;

        // Build grant context with all verification inputs
        // Note: in a full implementation, approver_cert and subject_cert would
        // come from separate lookups. For now we use the sender cert as approver.
        let ctx = GrantContext {
            own_pubkey: self.own_pubkey,
            approver_cert: sender_cert.clone(),
            subject_cert: sender_cert,
            trusted_ca_keys: self.trusted_ca_keys,
            intent_table: self.intent_table,
            sender_table: self.sender_table,
            now_ms,
            first_receipt_ms: now_ms,
            t_max_s: T_MAX_S_DEFAULT,
            t_recv_s: T_RECV_S_DEFAULT,
            already_consumed: hooks.already_consumed,
            is_revoked: hooks.is_revoked,
        };

        let outcome = verify_grant_then(env, &grant, &ctx, hooks.execute_effect)?;

        match outcome {
            EffectOutcome::Fired => Ok(Outcome::GrantExecuted),
            EffectOutcome::Refused => Ok(Outcome::EffectRefused),
        }
    }

    fn dispatch_refusal(
        &mut self,
        env: &Envelope<'_>,
        hooks: &Hooks<'a>,
        now_ms: u64,
    ) -> Result<Outcome, DispatchError> {
        let refusal = parse_refusal(env.body).map_err(|_| DispatchError::BadBody)?;

        let approver_cert = (hooks.cert_for_sender)(env.sender)
            .ok_or(DispatchError::UnknownSender)?;

        let mut ctx = RefusalContext {
            trusted_ca_keys: self.trusted_ca_keys,
            approver_cert,
            now_ms,
            intent_table: self.intent_table,
        };

        verify_refusal_then(env, &refusal, &mut ctx, hooks.on_rejected)?;

        Ok(Outcome::RefusalApplied)
    }
}
