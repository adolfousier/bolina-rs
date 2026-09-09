//! Rung E — Zig interop sanity (v0.6.1). Runs ONCE per soak session, before
//! the A-D loop; failure aborts the soak (no machine hours on a client that
//! cannot talk to the reference implementation).
//!
//! Anti-symmetry core: the client instantiates the FROZEN VECTOR AGENT
//! identity (kex_seed + Ed25519 seed from vectors.json), so the handshake
//! static equals the frozen cert's kex_pub (F1 passes), the binding frame
//! carries the frozen CA-signed cert, and the admitted envelope is the
//! frozen intent wire signed by that same identity. A shared codec bug
//! cannot cancel itself out: every byte the daemon verifies was produced by
//! the Zig reference, not by this client.
//!
//! Logistics (owner decision): rung E runs on the OWNER's machine against
//! the sealed Zig binary. The wrapper's `rung-e` mode runs this ladder
//! alone and prints a verdict; the dev machine never needs a Zig toolchain.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use bolina::transport::noise::KeyPair;
use ed25519_dalek::SigningKey;

use crate::handshake;
use crate::ladder_a::RoundLog;
use crate::ladder_d::{http_request, parse_sse};

struct FrozenIdentity {
    agent_kex: KeyPair,
    agent_sig: SigningKey,
    cert_wire: Vec<u8>,
    intent_wire: Vec<u8>,
    /// The frozen intent's id (32 hex chars), straight from the vector
    /// fields - e4 queries the reference's state route with it.
    intent_id_hex: String,
}

fn load_identity() -> Result<FrozenIdentity, String> {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/vectors.json"))
        .map_err(|e| format!("open vectors.json: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("parse vectors.json: {e}"))?;
    let hex32 = |s: &serde_json::Value, what: &str| -> Result<[u8; 32], String> {
        let h = s.as_str().ok_or_else(|| format!("{what}: not a string"))?;
        let b = hex::decode(h).map_err(|e| format!("{what}: bad hex: {e}"))?;
        let blen = b.len();
        let out: [u8; 32] = b.try_into().map_err(|_| format!("{what}: expected 32B, got {blen}B"))?;
        Ok(out)
    };
    let agent = &v["keys"]["agent"];
    let cert_wire = hex::decode(v["structures"]["cert"]["wire_hex"].as_str().ok_or("cert.wire_hex missing")?)
        .map_err(|e| format!("cert wire: {e}"))?;
    let intent_wire = hex::decode(v["structures"]["envelope_intent"]["wire_hex"].as_str().ok_or("envelope_intent.wire_hex missing")?)
        .map_err(|e| format!("intent wire: {e}"))?;
    let intent_id_hex = v["structures"]["envelope_intent"]["fields"]["body_intent_id"]
        .as_str()
        .ok_or("envelope_intent.fields.body_intent_id missing")?
        .to_string();
    Ok(FrozenIdentity {
        agent_kex: KeyPair::from_secret(hex32(&agent["kex_seed"], "agent.kex_seed")?),
        agent_sig: SigningKey::from_bytes(&hex32(&agent["seed"], "agent.seed")?),
        cert_wire,
        intent_wire,
        intent_id_hex,
    })
}

pub fn run(
    socket: &UdpSocket,
    daemon: SocketAddr,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    round: u32,
    control: SocketAddr,
    control_token: Option<&str>,
    _timeout: Duration,
) -> RoundLog {
    let mut log = RoundLog {
        steps: Vec::new(),
        frozen: "identity+cert+intent: 100% frozen vector material (agent kex_seed/seed/cert/envelope)".into(),
        ok: false,
        failed_at: None,
    };

    let id = match load_identity() {
        Ok(i) => i,
        Err(e) => return log.fail("e1.identity", e),
    };
    log = log.step("e1.identity", format!("frozen agent identity loaded (cert {}B, intent {}B)", id.cert_wire.len(), id.intent_wire.len()));

    // Handshake + binding through the shared path, with the FROZEN identity
    // and the FROZEN CA-signed cert. F1: cert.kex_pub == handshake static,
    // because the handshake static IS the frozen agent kex key.
    let (mut hs, bind_n) = match handshake::open_bound_with(
        socket, daemon, id.agent_kex, id.agent_sig.clone(), id.cert_wire.clone(),
        daemon_kex_pub, daemon_sig_pub, round,
    ) {
        Ok(pair) => pair,
        Err(e) => return log.fail("e2.session", format!("{e} - no interop with the Zig daemon; ABORT SOAK")),
    };
    let daemon_index = hs.daemon_index;
    let send_key_hex = hex::encode(&hs.session.send.key[..8]);
    let handshake_hash_hex = hex::encode(&hs.result.handshake_hash[..8]);
    let counter_after_bind = hs.session.send.counter;
    log = log.step("e2.session", format!(
        "msg2 verified + binding sent ({}B) - Rust initiator <-> Zig responder INTEROP, F1 coherent | receiver_index={} send_key[0..8]={} handshake_hash[0..8]={} counter_after_bind={}",
        bind_n, daemon_index, send_key_hex, handshake_hash_hex, counter_after_bind
    ));

    // e2 effect observation (method point, Daniel 2026-09-08: "a step that
    // does not observe the effect should not count as a step"). The
    // bound-require-mode reference pushes its OWN binding frame right after
    // the handshake commit (Zig daemon.zig handleHandshake -> sendBindingFrame;
    // BE-TR-01 is both directions). Opening it proves what no client-side
    // claim can: the daemon committed THIS session, its transcript hash is
    // byte-identical to ours (the frame's signature is Ed25519 over 0x05||h
    // by the provisioned executor key), and its cert material equals the
    // provisioned identity (F1 symmetric).
    let mut push = vec![0u8; 2048];
    let pn = match socket.recv_from(&mut push) {
        Ok((n, _)) => n,
        Err(e) => return log.fail(
            "e2.push",
            format!("no daemon-pushed binding frame ({e}) - bound-require mode pushes one right after commit; is cert.bin provisioned? (unbound-accept never pushes); ABORT SOAK"),
        ),
    };
    if push[0] != 4 {
        return log.fail("e2.push", format!("expected transport type 4, got {}", push[0]));
    }
    let push_ctr = u64::from_be_bytes(push[8..16].try_into().unwrap());
    let mut ppt = vec![0u8; pn];
    let n_pt = match hs.session.open(&push[..pn], push_ctr, &mut ppt) {
        Ok(n) => n,
        Err(e) => return log.fail("e2.push", format!("daemon binding frame did not open under our recv key: {e:?} - transcript or key-split divergence; ABORT SOAK")),
    };
    use bolina::transport::binding::DOMAIN_BINDING;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if n_pt < 2 + 64 {
        return log.fail("e2.push", format!("pushed plaintext too short: {n_pt}B"));
    }
    let cert_len = u16::from_be_bytes([ppt[0], ppt[1]]) as usize;
    if n_pt != 2 + cert_len + 64 {
        return log.fail("e2.push", format!("pushed plaintext {n_pt}B != 2 + cert({cert_len}) + 64"));
    }
    let dcert = &ppt[2..2 + cert_len];
    let dsig = match Signature::from_slice(&ppt[2 + cert_len..n_pt]) {
        Ok(s) => s,
        Err(e) => return log.fail("e2.push", format!("pushed sig parse: {e}")),
    };
    // Cert wire: ver(1) role(1) sig_pub(32) kex_pub(32) ... (SPEC 3.1)
    if cert_len < 66 {
        return log.fail("e2.push", format!("pushed cert too short: {cert_len}B"));
    }
    let d_sig_pub: [u8; 32] = dcert[2..34].try_into().unwrap();
    let d_kex_pub: [u8; 32] = dcert[34..66].try_into().unwrap();
    if d_sig_pub != daemon_sig_pub || d_kex_pub != daemon_kex_pub {
        return log.fail(
            "e2.push",
            "pushed cert keys != provisioned executor identity (--zig-sig-pub / --zig-kex-pub); ABORT SOAK".to_string(),
        );
    }
    let vk = match VerifyingKey::from_bytes(&d_sig_pub) {
        Ok(k) => k,
        Err(e) => return log.fail("e2.push", format!("daemon sig pubkey invalid: {e}")),
    };
    let push_input = [vec![DOMAIN_BINDING], hs.result.handshake_hash.to_vec()].concat();
    if vk.verify(&push_input, &dsig).is_err() {
        return log.fail(
            "e2.push",
            "daemon binding sig does NOT verify over 0x05||our handshake_hash - transcript hash divergence; ABORT SOAK".to_string(),
        );
    }
    log = log.step("e2.push", format!(
        "daemon's own binding frame opened ({}B wire, {}B pt, counter {}): sig over 0x05||h VERIFIED against provisioned executor - transcript hash byte-identical, cross-signed; F1 symmetric (cert.kex_pub == --zig-kex-pub)",
        pn, n_pt, push_ctr
    ));

    // Envelope: frozen intent wire verbatim (sealed fresh, bytes frozen).
    let mut pkt = vec![0u8; id.intent_wire.len() + 64];
    let n_env = match hs.session.seal(&mut pkt, &id.intent_wire) {
        Ok(n) => n,
        Err(e) => return log.fail("e3.envelope", format!("seal: {e:?}")),
    };
    if let Err(e) = socket.send_to(&pkt[..n_env], daemon) {
        return log.fail("e3.envelope", format!("send: {e}"));
    }
    log = log.step("e3.envelope", format!("frozen intent envelope sent ({}B wire) -> expect admission", n_env));

    // e4 verdict channel - declared delta of the sealed reference (design
    // §5.1): the Zig daemon DROPS wire-dispatch outcomes at the main loop
    // (`_ = handleDatagram`, main.zig), publishes only grant lifecycle and
    // HTTP-admitted intents to /v1/events, and increments
    // bolina_intents_admitted_total only in POST /v1/intents (control_api.zig
    // postIntent). A wire-path admission lands in the SHARED intent table
    // (main.zig: Api.table = &d.dispatcher.intents) and is observable via
    // GET /v1/intents/<32hex> -> 200 "pending" (getIntentState scans the same
    // table dispatch admits into). Watching SSE can never pass against the
    // reference, no matter how perfect the interop is. The Zig control plane
    // requires its boot token (403 without) - the wrapper passes it via
    // --control-token (--zig-token in rung-e mode).
    let state_path = format!("/v1/intents/{}", id.intent_id_hex);
    match http_request(control, "GET", &state_path, None, control_token, _timeout) {
        Ok((status, body)) => {
            if status == 403 {
                return log.fail(
                    "e4.state",
                    format!("GET {state_path} -> 403: control-plane token missing or wrong - pass --zig-token <hex> (printed at Zig daemon boot, stored in <data_dir>/control.token); ABORT SOAK"),
                );
            }
            if status == 404 {
                return log.fail(
                    "e4.state",
                    format!("intent ABSENT from the reference table (GET {state_path} -> 404) - the envelope was silently dropped (binding or dispatch); ABORT SOAK"),
                );
            }
            if status != 200 || !body.starts_with("pending") {
                return log.fail("e4.state", format!("GET {state_path} -> {status} {body:?}, expected 200 \"pending\""));
            }
            // Informational: SSE count. Zero intent_admitted events on the
            // reference is EXPECTED for wire admissions (declared delta
            // above), so it is logged, never judged.
            let sse_note = match http_request(control, "GET", "/v1/events?since=0", None, control_token, _timeout) {
                Ok((200, sse_body)) => format!(
                    "; SSE carries {} event(s) (reference publishes grant lifecycle + HTTP admissions only)",
                    parse_sse(&sse_body).len()
                ),
                _ => "; SSE unread".to_string(),
            };
            log = log.step("e4.state", format!(
                "wire-admitted intent PENDING in the reference table (GET {state_path} -> 200 \"pending\"){sse_note} - first-admission proof requires a freshly booted daemon"
            ));
        }
        Err(e) => return log.fail("e4.state", format!("{e} - cannot reach Zig control plane; ABORT SOAK")),
    }

    let mut log = log.step("e.verdict", "RUNG E PASS: Rust client <-> Zig daemon handshake + binding (cross-signed transcript) + wire admission confirmed via the reference's own state route".to_string());
    log.ok = true;
    log
}
