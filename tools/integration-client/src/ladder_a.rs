//! Ladder A - happy path: handshake, binding frame, intent, grant, effect.
//!
//! Design: docs/w12-integration-harness-design.md sections 3-5.
//! Frozen policy (section 5.3): round 0 of a daemon epoch sends the frozen
//! vector bytes (intent full envelope; grant body inside a fresh envelope
//! header). The effect body stays frozen every round - declared in the
//! round log: the vector IS the Zig reference for those bytes and building
//! evidence spans client-side would duplicate it.
//!
//! Against an unwired daemon the expected failure is a msg2 timeout - the
//! TODO->failure mapping from design section 9. That is a PASS for the
//! wiring matrix, not a bug.

use std::net::{SocketAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use bolina::codec::{self, Grant, Intent};
use bolina::keys as bkeys;
use bolina::transport::binding::DOMAIN_BINDING;
use bolina::transport::session::{Session, HEADER_SIZE};
use ed25519_dalek::Signer;

use crate::handshake;
use crate::keys::ClientKeys;

const EFFECT_BODY_FROZEN_ALWAYS: &str = "effect:body@always";

pub struct RoundLog {
    pub steps: Vec<(&'static str, String)>,
    pub frozen: String,
    pub ok: bool,
    pub failed_at: Option<&'static str>,
}

impl RoundLog {
    pub fn step(mut self, name: &'static str, msg: String) -> Self {
        self.steps.push((name, msg));
        self
    }
    pub fn fail(mut self, name: &'static str, msg: String) -> Self {
        self.steps.push((name, format!("FAIL: {msg}")));
        self.ok = false;
        self.failed_at = Some(name);
        self
    }
}

pub struct Frozen {
    pub intent_wire: Vec<u8>,
    pub grant_body: Vec<u8>,
    pub effect_body: Vec<u8>,
}

/// Load the Zig-reference bytes. Fixed path: the client always runs from
/// tools/integration-client; vectors live in test/ at the repo root.
pub fn load_frozen() -> Result<Frozen, String> {
    #[derive(serde::Deserialize)]
    struct Wire {
        wire_hex: String,
    }
    #[derive(serde::Deserialize)]
    struct Structs {
        envelope_intent: Wire,
        grant: Wire,
        effect: Wire,
    }
    #[derive(serde::Deserialize)]
    struct Vectors {
        structures: Structs,
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/vectors.json");
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let v: Vectors = serde_json::from_str(&raw).map_err(|e| format!("parse vectors.json: {e}"))?;
    let hexify = |s: &String| hex::decode(s).map_err(|e| format!("vectors hex: {e}"));
    Ok(Frozen {
        intent_wire: hexify(&v.structures.envelope_intent.wire_hex)?,
        grant_body: hexify(&v.structures.grant.wire_hex)?,
        effect_body: hexify(&v.structures.effect.wire_hex)?,
    })
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deterministic 32-byte tag (channel id) from the round identity.
pub fn channel_for(seed: u64, round: u32) -> [u8; 32] {
    let fp = bkeys::fingerprint(format!("{seed}:{round}:channel").as_bytes());
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fp);
    out[16..].copy_from_slice(&fp);
    out
}

pub fn id16(seed: u64, round: u32, what: &str) -> [u8; 16] {
    let fp = bkeys::fingerprint(format!("{seed}:{round}:{what}").as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&fp);
    id
}

/// Envelope tbs = header + body (everything encode_envelope emits before
/// the trailing 64-byte signature).
fn envelope_tbs(
    channel: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    ts: u64,
    body_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(64 + body.len());
    tbs.push(2u8); // envelope version
    tbs.extend_from_slice(channel);
    tbs.extend_from_slice(sender);
    tbs.extend_from_slice(&seq.to_be_bytes());
    tbs.push(0); // parent_count, no parents
    tbs.extend_from_slice(&ts.to_be_bytes());
    tbs.push(body_type);
    tbs.extend_from_slice(&(body.len() as u32).to_be_bytes());
    tbs.extend_from_slice(body);
    tbs
}

pub fn build_envelope(
    sig_key: &ed25519_dalek::SigningKey,
    channel: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    body_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let ts = now_ms();
    let tbs = envelope_tbs(channel, sender, seq, ts, body_type, body);
    let sig_input = [vec![codec::DOMAIN_ENVELOPE], tbs.clone()].concat();
    let sig = sig_key.sign(&sig_input);
    let mut wire = tbs;
    wire.extend_from_slice(sig.to_bytes().as_slice());
    wire
}

pub fn send_sealed(
    socket: &UdpSocket,
    daemon: SocketAddr,
    session: &mut Session,
    plaintext: &[u8],
) -> Result<usize, String> {
    let mut wire = vec![0u8; HEADER_SIZE + plaintext.len() + 16];
    let n = session.seal(&mut wire, plaintext).map_err(|e| format!("seal: {e:?}"))?;
    wire.truncate(n);
    socket.send_to(&wire, daemon).map_err(|e| format!("send_to: {e}"))?;
    Ok(n)
}

fn grant_body(ck: &ClientKeys, seed: u64, round: u32, not_after: u64) -> Vec<u8> {
    let gid = id16(seed, round, "grant");
    let iid = id16(seed, round, "intent");
    let approver_pub = ck.approver.verifying_key().to_bytes();
    let subject_pub = ck.sig.verifying_key().to_bytes();
    let exec_pub = ck.sig.verifying_key().to_bytes();
    let resource = format!("bol:{}/harness/round{}", hex::encode([0u8; 8]), round);

    let mut tbs = Vec::with_capacity(220);
    tbs.push(1); // grant version
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

fn intent_body(seed: u64, round: u32) -> Vec<u8> {
    let iid = id16(seed, round, "intent");
    let res = format!("bol:{}/harness/round{}", hex::encode([0u8; 8]), round);
    let i = Intent {
        intent_id: &iid,
        resource_id: res.as_bytes(),
        action: b"read",
        rationale: b"harness ladder A",
    };
    codec::encode_intent(&i)
}

pub fn seq_for(round: u32, k: u64) -> u64 {
    (round as u64) * 10 + k
}

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
    // The round log IS the frozen= declaration required by acceptance.
    let frozen_decl = if round == 0 {
        format!("frozen=intent:full@r0,grant:body@r0,{EFFECT_BODY_FROZEN_ALWAYS} target={target}")
    } else {
        format!("frozen=intent:built,grant:built,{EFFECT_BODY_FROZEN_ALWAYS} target={target}")
    };
    let log = RoundLog {
        steps: Vec::new(),
        frozen: frozen_decl,
        ok: true,
        failed_at: None,
    };

    // Step 1+2: handshake. Failure here against an unwired daemon is the
    // expected matrix outcome, and the error text says so.
    let (mut log, mut hs) = match handshake::exchange(socket, daemon, ck, daemon_kex_pub, daemon_sig_pub, round) {
        Ok(hs) => {
            let l1 = log.step("handshake.msg2", format!("msg2 ok, daemon_idx={}", hs.daemon_index));
            let l2 = l1.step(
                "handshake.finalize",
                format!("split ok, h={}", hex::encode(&hs.result.handshake_hash[..8])),
            );
            (l2.step("session", "client send state armed (counter 0)".into()), hs)
        }
        Err(e) => return log.fail("handshake.msg2", e),
    };

    // Step 3: binding frame - first type-4 packet, counter 0.
    // Plaintext = cert || binding_sig over DOMAIN_BINDING || handshake_hash.
    let t = now_ms();
    let cert = crate::keys::build_cert(ck, t.saturating_sub(1_000), t + 3_600_000);
    let bind_input = [vec![DOMAIN_BINDING], hs.result.handshake_hash.to_vec()].concat();
    let bind_sig = ck.sig.sign(&bind_input);
    let cert_len = cert.len();
    let binding_pt = {
        let mut pt = cert;
        pt.extend_from_slice(bind_sig.to_bytes().as_slice());
        pt
    };
    let n = match send_sealed(socket, daemon, &mut hs.session, &binding_pt) {
        Ok(n) => n,
        Err(e) => return log.fail("binding.sent", e),
    };
    log = log.step("binding.sent", format!("{n} bytes (cert {cert_len} + sig 64)"));

    // Step 4: envelopes. Frozen policy per the round-log declaration.
    let frozen = match load_frozen() {
        Ok(f) => f,
        Err(e) => return log.fail("envelopes.frozen", e),
    };
    let channel = channel_for(seed, round);
    let sender = ck.sig.verifying_key().to_bytes();

    // 4a. intent: round 0 = the frozen FULL envelope verbatim.
    if round == 0 {
        let n = match send_sealed(socket, daemon, &mut hs.session, &frozen.intent_wire) {
            Ok(n) => n,
            Err(e) => return log.fail("env.intent", e),
        };
        log = log.step("env.intent", format!("FROZEN full envelope (vector seq), {n} bytes on wire"));
    } else {
        let env = build_envelope(&ck.sig, &channel, &sender, seq_for(round, 1), codec::BODY_INTENT, &intent_body(seed, round));
        let n = match send_sealed(socket, daemon, &mut hs.session, &env) {
            Ok(n) => n,
            Err(e) => return log.fail("env.intent", e),
        };
        log = log.step("env.intent", format!("built, seq={} , {n} bytes on wire", seq_for(round, 1)));
    }

    // 4b. grant: round 0 = frozen body in a fresh envelope header.
    let grant_seq = seq_for(round, 2);
    let grant_payload = if round == 0 {
        frozen.grant_body.clone()
    } else {
        grant_body(ck, seed, round, now_ms() + 60_000)
    };
    let tag = if round == 0 { "FROZEN body" } else { "built" };
    let env = build_envelope(&ck.sig, &channel, &sender, grant_seq, codec::BODY_GRANT, &grant_payload);
    let n = match send_sealed(socket, daemon, &mut hs.session, &env) {
        Ok(n) => n,
        Err(e) => return log.fail("env.grant", e),
    };
    log = log.step("env.grant", format!("{tag}, seq={grant_seq}, {n} bytes on wire"));

    // 4c. effect: body ALWAYS frozen (declared).
    let effect_seq = seq_for(round, 3);
    let env = build_envelope(&ck.sig, &channel, &sender, effect_seq, codec::BODY_EFFECT, &frozen.effect_body);
    let n = match send_sealed(socket, daemon, &mut hs.session, &env) {
        Ok(n) => n,
        Err(e) => return log.fail("env.effect", e),
    };
    log = log.step("env.effect", format!("FROZEN body, seq={effect_seq}, {n} bytes on wire"));

    log.step("ladder.done", "3 envelopes sent; admission counts via /v1/events land with task 5".into())
}
