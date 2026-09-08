//! Ladder C — rejection path. 100% frozen vector bytes, every round.
//!
//! NOTE: no client codec involvement in C envelope bytes (raw hex from
//! vectors.json). Per the frozen-only physics note in the design: stale-seq
//! and unknown-parents wire variants are UNREACHABLE from a single frozen
//! full envelope (the envelope sig gate fires before seq/parents checks),
//! so this ladder runs: duplicate + transport replay + truncated parse +
//! sig-patched byte, yielding 1 admission + 1 idempotent + 3 rejections.
//! The stale/unknown-parents rejections stay covered daemon-side by the W11
//! named tests and become wire-reachable via ladder A's built path (W12
//! task 8), where the client codec builds signed distinct envelopes.

use std::net::{SocketAddr, UdpSocket};

use crate::handshake;
use crate::keys::ClientKeys;
use crate::ladder_a::{RoundLog, load_frozen};
use bolina::transport::session::HEADER_SIZE;

pub fn run(
    socket: &UdpSocket,
    daemon: SocketAddr,
    ck: &ClientKeys,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    round: u32,
    _zig: bool,
) -> RoundLog {
    let mut log = RoundLog {
        steps: Vec::new(),
        frozen: "intent:full@every-round(grant/effect bodies unused in C)".into(),
        ok: false,
        failed_at: None,
    };

    // Freshness classification: always runs, fails fast on a broken file.
    log = match load_frozen() {
        Ok(fz) => log.step("vectors.load", format!("intent wire {}B loaded from vectors.json", fz.intent_wire.len())),
        Err(e) => return log.fail("vectors.load", e),
    };

    // Session: handshake + binding (shared with A/B).
    log = log.step("vectors.freshness", "C uses raw frozen intent bytes verbatim; classification not applicable".into());
    let (mut log, mut hs) = match handshake::open_bound_session(
        socket, daemon, ck, daemon_kex_pub, daemon_sig_pub, round,
    ) {
        Ok((hs, bind_n)) => (
            log.step("c0.session", format!("bound: msg2 ok (daemon_idx={}), binding sent ({}B)", hs.daemon_index, bind_n)),
            hs,
        ),
        Err(e) => return log.fail("session", e),
    };

    let frozen = match load_frozen() {
        Ok(f) => f,
        Err(e) => return log.fail("vectors.reload", e),
    };

    // c1: frozen intent, fresh seal -> expect admission.
    let mut pkt = vec![0u8; HEADER_SIZE + frozen.intent_wire.len() + 16];
    let n1 = match hs.session.seal(&mut pkt, &frozen.intent_wire) {
        Ok(n) => n,
        Err(e) => return log.fail("c1.seal", format!("{e:?}")),
    };
    if let Err(e) = socket.send_to(&pkt[..(n1 as usize)], daemon) {
        return log.fail("c1.send", format!("{e:?}"));
    }
    log = log.step("c1.admission", format!("frozen intent sent ({}B) -> expect admit", n1 + HEADER_SIZE + 16));

    // c2: same frozen intent, NEW counter -> expect idempotent duplicate at the ledger.
    let mut pkt2 = vec![0u8; HEADER_SIZE + frozen.intent_wire.len() + 16];
    let n2 = match hs.session.seal(&mut pkt2, &frozen.intent_wire) {
        Ok(n) => n,
        Err(e) => return log.fail("c2.seal", format!("{e:?}")),
    };
    if let Err(e) = socket.send_to(&pkt2[..n2], daemon) {
        return log.fail("c2.send", format!("{e:?}"));
    }
    log = log.step("c2.idempotent", "same envelope, new transport counter -> expect idempotent-duplicate (ledger dedupe, no advance)".to_string());

    // c3: byte-identical transport replay of the c2 packet -> expect ReplayWindow rejection.
    if let Err(e) = socket.send_to(&pkt2[..n2], daemon) {
        return log.fail("c3.send", format!("{e:?}"));
    }
    log = log.step("c3.replay", "exact c2 packet bytes re-sent -> expect transport ReplayWindow rejection (same counter)".to_string());

    // c4: truncated frozen wire -> expect parse Truncated rejection.
    let cut = &frozen.intent_wire[..frozen.intent_wire.len() - 1];
    let mut pkt4 = vec![0u8; HEADER_SIZE + cut.len() + 16];
    let n4 = match hs.session.seal(&mut pkt4, cut) {
        Ok(n) => n,
        Err(e) => return log.fail("c4.seal", format!("{e:?}")),
    };
    if let Err(e) = socket.send_to(&pkt4[..n4], daemon) {
        return log.fail("c4.send", format!("{e:?}"));
    }
    log = log.step("c4.truncated", format!("frozen wire minus 1B ({}B) -> expect parse Truncated rejection", cut.len()));

    // c5: sig-patched body_type byte (2 -> 5) -> expect envelope sig rejection.
    let mut patched = frozen.intent_wire.clone();
    patched[73] = 5; // body_type field: 1+32+32+8 = 73 header bytes before body_type
    let mut pkt5 = vec![0u8; HEADER_SIZE + patched.len() + 16];
    let n5 = match hs.session.seal(&mut pkt5, &patched) {
        Ok(n) => n,
        Err(e) => return log.fail("c5.seal", format!("{e:?}")),
    };
    if let Err(e) = socket.send_to(&pkt5[..n5], daemon) {
        return log.fail("c5.send", format!("{e:?}"));
    }
    log = log.step("c5.sig-patched", "body_type byte 2->5, sig untouched -> expect envelope sig rejection".to_string());

    // Summary: counts asserted via /v1/events SSE in task 5/6. Today the wire
    // side is complete; functional pass lands with task 8 wiring.
    let mut log = log.step("c.summary", "5 sends: expect 1 admit + 1 idempotent + 3 rejections (verified via SSE from task 5)".to_string());
    log.ok = true;
    log
}
