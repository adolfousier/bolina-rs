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
    Ok(FrozenIdentity {
        agent_kex: KeyPair::from_secret(hex32(&agent["kex_seed"], "agent.kex_seed")?),
        agent_sig: SigningKey::from_bytes(&hex32(&agent["seed"], "agent.seed")?),
        cert_wire,
        intent_wire,
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
    log = log.step("e2.session", format!("msg2 verified + binding sent ({}B) - Rust initiator <-> Zig responder INTEROP, F1 coherent", bind_n));

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

    // Admission visible in the Zig daemon event stream. The Zig control
    // plane requires its boot token (403 without it) — the wrapper passes
    // it via --control-token (--zig-token in rung-e mode).
    match http_request(control, "GET", "/v1/events?since=0", None, control_token, _timeout) {
        Ok((status, body)) => {
            if status == 403 {
                return log.fail(
                    "e4.events",
                    "GET /v1/events -> 403: control-plane token missing or wrong - pass --zig-token <hex> (printed at Zig daemon boot, stored in <data_dir>/control.token); ABORT SOAK".to_string(),
                );
            }
            if status != 200 {
                return log.fail("e4.events", format!("GET /v1/events -> {status}, expected 200"));
            }
            let events = parse_sse(&body);
            let admitted = events.iter().filter(|(t, _)| t == "intent_admitted").count();
            if admitted == 0 {
                let tags: Vec<&str> = events.iter().map(|(t, _)| t.as_str()).collect();
                return log.fail(
                    "e4.events",
                    format!("no intent_admitted in {} SSE events [{}] - envelope not admitted or ring not wired; ABORT SOAK (note: re-running rung E against a warm daemon yields an idempotent duplicate, which publishes no new event - restart the daemon for a clean rung E)",
                        events.len(), tags.join(",")),
                );
            }
            log = log.step("e4.events", format!("intent_admitted x{admitted} visible in Zig daemon SSE stream"));
        }
        Err(e) => return log.fail("e4.events", format!("{e} - cannot reach Zig control plane; ABORT SOAK")),
    }

    let mut log = log.step("e.verdict", "RUNG E PASS: Rust client <-> Zig daemon handshake + binding + admission confirmed".to_string());
    log.ok = true;
    log
}
