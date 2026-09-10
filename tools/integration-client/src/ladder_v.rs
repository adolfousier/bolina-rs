//! Ladder V — volume soak: N envelopes per session with batch metrics.
//!
//! Exercises the admission path under sustained load: hash store, replay
//! windows, parents-before-seq, intent table, ledger growth. One session
//! (handshake + binding), N envelopes — the 16-slot table constrains
//! concurrent sessions, not envelope volume.
//!
//! Metrics per batch (100 envelopes): latency (ms), throughput (env/s).
//! Closes G4 Honest Declaration 1: sustained load on the integrated path.

use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use bolina::codec::{self, Intent};
use bolina::transport::binding::DOMAIN_BINDING;
use ed25519_dalek::Signer;

use crate::handshake;
use crate::keys::ClientKeys;
use crate::ladder_a::{
    build_envelope, channel_for, id16, now_ms, resource_for, send_sealed,
    RoundLog,
};

const BATCH_SIZE: usize = 100;

pub fn run(
    socket: &UdpSocket,
    daemon: SocketAddr,
    ck: &ClientKeys,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    seed: u64,
    round: u32,
    envelopes_per_session: usize,
) -> RoundLog {
    let log = RoundLog {
        steps: Vec::new(),
        frozen: format!("volume: {envelopes_per_session} envelopes/session, batches of {BATCH_SIZE}"),
        ok: true,
        failed_at: None,
    };

    // Step 1: handshake
    let (mut log, mut hs) = match handshake::exchange(socket, daemon, ck, daemon_kex_pub, daemon_sig_pub, round) {
        Ok(hs) => {
            let l = log.step("handshake.msg2", format!("msg2 ok, daemon_idx={}", hs.daemon_index));
            (l.step("session", "client send state armed".into()), hs)
        }
        Err(e) => return log.fail("handshake.msg2", e),
    };

    // Step 2: binding frame
    let t = now_ms();
    let cert = crate::keys::build_cert(ck, t.saturating_sub(1_000), t + 3_600_000);
    let bind_input = [vec![DOMAIN_BINDING], hs.result.handshake_hash.to_vec()].concat();
    let bind_sig = ck.sig.sign(&bind_input);
    let binding_pt = {
        let mut pt = cert;
        pt.extend_from_slice(bind_sig.to_bytes().as_slice());
        pt
    };
    match send_sealed(socket, daemon, &mut hs.session, &binding_pt) {
        Ok(n) => log = log.step("binding.sent", format!("{n} bytes")),
        Err(e) => return log.fail("binding.sent", e),
    }

    // Step 3: volume envelopes
    let channel = channel_for(seed, round);
    let sender = ck.sig.verifying_key().to_bytes();
    let resource = resource_for(&daemon_sig_pub, "v");

    let total_batches = (envelopes_per_session + BATCH_SIZE - 1) / BATCH_SIZE;
    let total_start = Instant::now();
    let mut total_sent: usize = 0;
    let mut batch_latencies: Vec<u64> = Vec::with_capacity(total_batches);

    for batch in 0..total_batches {
        let batch_start = Instant::now();
        let batch_count = std::cmp::min(BATCH_SIZE, envelopes_per_session - total_sent);

        for i in 0..batch_count {
            let env_idx = total_sent + i;
            // Each envelope: unique intent_id, unique seq, same resource
            let iid = id16(seed, round * 10000 + env_idx as u32, "vol-intent");
            let seq = (round as u64) * 1_000_000 + env_idx as u64 + 100; // offset past binding
            let rationale_str = format!("volume batch {batch} env {i}");
            let body = {
                let intent = Intent {
                    intent_id: &iid,
                    resource_id: resource.as_bytes(),
                    action: b"read",
                    rationale: rationale_str.as_bytes(),
                };
                codec::encode_intent(&intent)
            };
            let env = build_envelope(
                &ck.sig,
                &channel,
                &sender,
                seq,
                codec::BODY_INTENT,
                &body,
            );
            if let Err(e) = send_sealed(socket, daemon, &mut hs.session, &env) {
                return log.fail("env.volume", format!("batch {batch} env {i}: {e}"));
            }
        }

        let batch_ms = batch_start.elapsed().as_millis() as u64;
        let batch_throughput = if batch_ms > 0 {
            (batch_count as f64) / (batch_ms as f64 / 1000.0)
        } else {
            f64::INFINITY
        };
        batch_latencies.push(batch_ms);

        total_sent += batch_count;
        log = log.step(
            "batch",
            format!(
                "{batch}/{total_batches}: {batch_count} env in {batch_ms}ms ({batch_throughput:.0} env/s)"
            ),
        );
    }

    let total_ms = total_start.elapsed().as_millis() as u64;
    let total_throughput = if total_ms > 0 {
        (total_sent as f64) / (total_ms as f64 / 1000.0)
    } else {
        f64::INFINITY
    };

    // Summary metrics
    let p50 = percentile(&batch_latencies, 50);
    let p95 = percentile(&batch_latencies, 95);
    let p99 = percentile(&batch_latencies, 99);

    log = log.step(
        "volume.summary",
        format!(
            "{total_sent} envelopes in {total_ms}ms ({total_throughput:.0} env/s) | batch latency p50={p50}ms p95={p95}ms p99={p99}ms"
        ),
    );

    log.step("ladder.done", format!("volume soak complete: {total_sent} envelopes, {total_batches} batches"))
}

fn percentile(sorted_values: &[u64], p: usize) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let mut v = sorted_values.to_vec();
    v.sort();
    let idx = (v.len() * p + 99) / 100; // round up
    v[std::cmp::min(idx, v.len() - 1)]
}
