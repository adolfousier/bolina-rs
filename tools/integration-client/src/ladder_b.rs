//! Ladder B - refusal path: expired grant, then the refusal envelope.
//!
//! Design section 4 (Ladder B):
//!   1. handshake + binding
//!   2. grant envelope with expired not_after -> admitted, verify -> Expired
//!   3. refusal envelope for that grant -> admitted, verify_refusal -> OK
//!      Expected: 2 admissions, 1 refusal outcome, 0 rejections.
//!
//! Freshness classification (design 5.3): at round start the FROZEN grant
//! vector is decoded and classified admit-able vs expired against the wall
//! clock; an expired vector is used verbatim for step 2 (it is naturally
//! the reference bytes for an expired grant), otherwise a client-built
//! expired grant is declared instead.

use std::net::{SocketAddr, UdpSocket};

use bolina::codec::{self, Grant, Refusal};
use ed25519_dalek::Signer;

use crate::handshake;
use crate::keys::ClientKeys;
use crate::ladder_a::{build_envelope, load_frozen, now_ms, seq_for, RoundLog};

const B_LANE: u64 = 5; // seq lane for ladder B (A uses 1..3, C uses 7..)
#[allow(clippy::too_many_arguments)]

pub fn run(
    socket: &UdpSocket,
    daemon: SocketAddr,
    ck: &ClientKeys,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    seed: u64,
    round: u32,
    zig: bool,
) -> RoundLog {
    let target = if zig { "zig-v0.6.1" } else { "rust" };
    let mut log = RoundLog {
        steps: Vec::new(),
        frozen: format!("frozen=grant:body-if-expired,refusal:built,{EFFECT_ALWAYS} target={target}"),
        ok: true,
        failed_at: None,
    };

    // Freshness classification of the frozen grant vector (logged ALWAYS).
    let frozen = match load_frozen() {
        Ok(f) => f,
        Err(e) => return log.fail("vectors.load", e),
    };
    let now = now_ms();
    let (vector_state, grant_payload) = match codec::parse_grant(&frozen.grant_body) {
        Ok(g) => {
            if g.not_after > now {
                let remain_s = (g.not_after - now) / 1_000;
                // Admit-able now, but it WILL expire: route the frozen bytes
                // to ladder B when their time comes, per design 5.3.
                (
                    format!("admit-able (expires in {remain_s}s) -> using client-built expired grant"),
                    client_expired_grant(ck, seed, round, now, &daemon_sig_pub),
                )
            } else {
                let ago_s = (now - g.not_after) / 1_000;
                (
                    format!("EXPIRED ({ago_s}s past) -> using frozen vector bytes verbatim"),
                    frozen.grant_body.clone(),
                )
            }
        }
        Err(e) => return log.fail("vectors.classify", format!("frozen grant parse: {e:?}")),
    };
    log = log.step("vectors.freshness", format!("grant vector: {vector_state}"));

    // Step 1: handshake + binding.
    let (mut log, mut hs) = match handshake::open_bound_session(
        socket, daemon, ck, daemon_kex_pub, daemon_sig_pub, round,
    ) {
        Ok((hs, bind_n)) => (
            log.step(
                "session",
                format!("bound: msg2 ok (daemon_idx={}), binding sent ({bind_n}B)", hs.daemon_index),
            ),
            hs,
        ),
        Err(e) => return log.fail("handshake.msg2", e),
    };

    let channel = crate::ladder_a::channel_for(seed, round);
    let sender = ck.sig.verifying_key().to_bytes();

    // Step 2: expired grant envelope.
    let g_seq = seq_for(round, B_LANE);
    let env = build_envelope(&ck.sig, &channel, &sender, g_seq, codec::BODY_GRANT, &grant_payload);
    let n = match crate::ladder_a::send_sealed(socket, daemon, &mut hs.session, &env) {
        Ok(n) => n,
        Err(e) => return log.fail("env.expired_grant", e),
    };
    log = log.step("env.expired_grant", format!("seq={g_seq}, {n}B; expect admission + Expired refusal"));

    // Step 3: refusal envelope for the expired grant's intent.
    // intent_id: the expired grant's own (frozen path) or the built one.
    let (r_intent_id, note): (Vec<u8>, &[u8]) = match codec::parse_grant(&grant_payload) {
        Ok(g) => (g.intent_id.to_vec(), b"grant expired"),
        Err(e) => return log.fail("env.refusal", format!("grant re-parse: {e:?}")),
    };
    let r_seq = seq_for(round, B_LANE + 1);
    let refusal_body = match build_refusal(ck, &r_intent_id, note) {
        Ok(b) => b,
        Err(e) => return log.fail("env.refusal", e),
    };
    let env = build_envelope(&ck.sig, &channel, &sender, r_seq, codec::BODY_REFUSAL, &refusal_body);
    let n = match crate::ladder_a::send_sealed(socket, daemon, &mut hs.session, &env) {
        Ok(n) => n,
        Err(e) => return log.fail("env.refusal", e),
    };
    log = log.step("env.refusal", format!("seq={r_seq}, {n}B; expect admission + verify OK"));

    log.step("ladder.done", "expired grant + refusal sent; counts via /v1/events land with task 5".into())
}

const EFFECT_ALWAYS: &str = "effect:n/a";

fn client_expired_grant(ck: &ClientKeys, seed: u64, round: u32, now: u64, daemon_sig_pub: &[u8; 32]) -> Vec<u8> {
    let gid = crate::ladder_a::id16(seed, round, "b-grant");
    let iid = crate::ladder_a::id16(seed, round, "b-intent");
    let approver_pub = ck.approver.verifying_key().to_bytes();
    let subject_pub = ck.sig.verifying_key().to_bytes();
    let exec_pub = ck.sig.verifying_key().to_bytes();
    let resource = crate::ladder_a::resource_for(daemon_sig_pub, "b");
    let not_after = now.saturating_sub(1_000); // expired 1s ago

    let mut tbs = Vec::with_capacity(220);
    tbs.push(1);
    tbs.extend_from_slice(&gid);
    tbs.extend_from_slice(&iid);
    tbs.extend_from_slice(&approver_pub);
    tbs.extend_from_slice(&subject_pub);
    tbs.extend_from_slice(&exec_pub);
    tbs.extend_from_slice(&(resource.len() as u16).to_be_bytes());
    tbs.extend_from_slice(resource.as_bytes());
    tbs.extend_from_slice(&[0u8; codec::LEN_ACTION_DIGEST]);
    tbs.extend_from_slice(&not_after.to_be_bytes());
    let sig_input = [vec![codec::DOMAIN_GRANT], tbs.clone()].concat();
    let sig = ck.approver.sign(&sig_input);
    let sig_bytes = sig.to_bytes();
    let g = Grant {
        version: 1,
        grant_id: &gid,
        intent_id: &iid,
        approver: &approver_pub,
        subject: &subject_pub,
        executor: &exec_pub,
        resource_id: resource.as_bytes(),
        action_digest: &[0u8; codec::LEN_ACTION_DIGEST],
        not_after,
        tbs: &tbs,
        sig: &sig_bytes,
    };
    codec::encode_grant(&g)
}

fn build_refusal(ck: &ClientKeys, intent_id: &[u8], note: &[u8]) -> Result<Vec<u8>, String> {
    let mut tbs = Vec::with_capacity(96);
    tbs.extend_from_slice(intent_id);
    tbs.extend_from_slice(&(note.len() as u16).to_be_bytes());
    tbs.extend_from_slice(note);
    let sig_input = [vec![codec::DOMAIN_REFUSAL], tbs.clone()].concat();
    let sig = ck.approver.sign(&sig_input);
    let sig_bytes = sig.to_bytes();
    let r = Refusal {
        intent_id,
        note,
        tbs: &tbs,
        sig: &sig_bytes,
    };
    Ok(codec::encode_refusal(&r))
}
