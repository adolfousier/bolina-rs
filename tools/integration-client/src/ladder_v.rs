//! Ladder V - volume soak: N envelopes per session with batch metrics.
//!
//! Exercises the admission path under sustained load: hash store, replay
//! windows, parents-before-seq, intent table, ledger growth. One session
//! (handshake + binding), N envelopes - the 16-slot table constrains
//! concurrent sessions, not envelope volume.
//!
//! Two fixes ride with the counters (pending-corrections #1):
//!  - the old inline binding omitted u16be(cert_len); the strictly-parsing
//!    daemon dropped it, so every V session was silently UNBOUND and all
//!    envelopes fell out before admission - the 8 h "volume" run was
//!    traffic, not admission. V now uses the shared framed path.
//!  - a step that does not observe its effect is not a step: V reads the
//!    daemon's /metrics wire counters before and after the batches and
//!    fails the round unless every sent envelope is accounted (inserted
//!    or StoreFull-rejected).

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use bolina::codec::{self, Intent};

use crate::handshake;
use crate::keys::ClientKeys;
use crate::ladder_a::{
    build_envelope, channel_for, id16, resource_for, send_sealed, RoundLog,
};
use crate::ladder_d::http_request;

const BATCH_SIZE: usize = 100;

/// Resource rotation: envelopes cycle through v0..v{V_ROTATION-1}. With one
/// shared resource the intent table (BE-GRANT-06) keeps the first intent
/// PENDING and holds every later one with r_intent_resource_held - measured
/// at 1 admission per 300 envelopes. Rotating lifts the workload to the
/// intent-table ceiling (MAX_PENDING=256), which is the dispatch load the
/// volume soak exists to measure - capped in practice by the resolver's
/// MAX_RESOURCES=32 set (Zig parity), which the wrapper computes and passes
/// as --v-rotation. Default only applies to manual runs.
pub const V_ROTATION: usize = 16;

/// Snapshot of the daemon's wire-path counters from /metrics.
#[derive(Debug, Default, PartialEq)]
pub struct MetricsSnapshot {
    pub admissions: u64,
    pub inserts: u64,
    pub storefull: u64,
    pub rejects: Vec<(String, u64)>,
}

pub fn parse_metrics(body: &str) -> Result<MetricsSnapshot, String> {
    let mut m = MetricsSnapshot::default();
    let (mut seen_a, mut seen_i, mut seen_s) = (false, false, false);
    for line in body.lines() {
        let (name, val) = match line.rsplit_once(' ') {
            Some(p) => p,
            None => continue,
        };
        let Ok(v) = val.parse::<u64>() else { continue };
        match name {
            "bolina_wire_admissions_total" => {
                m.admissions = v;
                seen_a = true;
            }
            "bolina_ledger_inserts_total" => {
                m.inserts = v;
                seen_i = true;
            }
            "bolina_ledger_storefull_total" => {
                m.storefull = v;
                seen_s = true;
            }
            other => {
                if let Some(cls) = other
                    .strip_prefix("bolina_wire_rejects_total{class=\"")
                    .and_then(|s| s.strip_suffix("\"}"))
                {
                    m.rejects.push((cls.to_string(), v));
                }
            }
        }
    }
    if !(seen_a && seen_i && seen_s) {
        return Err(format!(
            "metrics body missing wire counters (admissions={seen_a} inserts={seen_i} storefull={seen_s})"
        ));
    }
    Ok(m)
}

fn read_metrics(
    control: SocketAddr,
    token: Option<&str>,
    timeout: Duration,
) -> Result<MetricsSnapshot, String> {
    let (status, body) = http_request(control, "GET", "/metrics", None, token, timeout)?;
    if status != 200 {
        return Err(format!("/metrics: status {status}"));
    }
    parse_metrics(&body)
}

fn reject_delta(base: &MetricsSnapshot, end: &MetricsSnapshot) -> String {
    let mut parts = String::new();
    for (name, val) in &end.rejects {
        let prev = base
            .rejects
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        let d = val.saturating_sub(prev);
        if d > 0 {
            parts.push_str(&format!(" {name}={d}"));
        }
    }
    if parts.is_empty() {
        " none".to_string()
    } else {
        parts
    }
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
    envelopes_per_session: usize,
    v_rotation: usize,
    control: SocketAddr,
    token: Option<&str>,
    timeout: Duration,
) -> RoundLog {
    let log = RoundLog {
        steps: Vec::new(),
        frozen: format!(
            "volume: {envelopes_per_session} envelopes/session, batches of {BATCH_SIZE}, rotation {v_rotation}"
        ),
        ok: true,
        failed_at: None,
    };

    // Handshake + binding, shared framed path.
    let (mut hs, bind_n) =
        match handshake::open_bound_session(socket, daemon, ck, daemon_kex_pub, daemon_sig_pub, round)
        {
            Ok(v) => v,
            Err(e) => return log.fail("session", e),
        };
    let mut log = log
        .step("handshake.msg2", format!("msg2 ok, daemon_idx={}", hs.daemon_index))
        .step("session", "client send state armed".into())
        .step("binding.sent", format!("{bind_n} bytes (u16be framed)"));

    // Baseline counters: observation is mandatory before any traffic.
    // Settle first: ladders A-D ran just before V, and the daemon drains
    // roughly one packet per 10 ms loop tick - its tail (~7 packets) must
    // land before the baseline, or it would leak into V's window.
    std::thread::sleep(Duration::from_millis(200));
    let base = match read_metrics(control, token, timeout) {
        Ok(m) => m,
        Err(e) => return log.fail("metrics.baseline", e),
    };
    log = log.step(
        "metrics.baseline",
        format!(
            "admissions={} inserts={} storefull={}",
            base.admissions, base.inserts, base.storefull
        ),
    );

    // Volume envelopes.
    let channel = channel_for(seed, round);
    let sender = ck.sig.verifying_key().to_bytes();

    let total_batches = (envelopes_per_session + BATCH_SIZE - 1) / BATCH_SIZE;
    let total_start = Instant::now();
    let mut total_sent: usize = 0;
    let mut batch_latencies: Vec<u64> = Vec::with_capacity(total_batches);

    for batch in 0..total_batches {
        let batch_start = Instant::now();
        let batch_count = std::cmp::min(BATCH_SIZE, envelopes_per_session - total_sent);

        for i in 0..batch_count {
            let env_idx = total_sent + i;
            let iid = id16(seed, round * 10000 + env_idx as u32, "vol-intent");
            let seq = (round as u64) * 1_000_000 + env_idx as u64 + 100;
            let lane = env_idx % v_rotation.max(1);
            let resource = resource_for(&daemon_sig_pub, &format!("v{lane}"));
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
            format!("{batch}/{total_batches}: {batch_count} env in {batch_ms}ms ({batch_throughput:.0} env/s)"),
        );
    }

    let total_ms = total_start.elapsed().as_millis() as u64;
    let total_throughput = if total_ms > 0 {
        (total_sent as f64) / (total_ms as f64 / 1000.0)
    } else {
        f64::INFINITY
    };
    let p50 = percentile(&batch_latencies, 50);
    let p95 = percentile(&batch_latencies, 95);
    let p99 = percentile(&batch_latencies, 99);
    log = log.step(
        "volume.summary",
        format!(
            "{total_sent} envelopes in {total_ms}ms ({total_throughput:.0} env/s) | batch latency p50={p50}ms p95={p95}ms p99={p99}ms"
        ),
    );

    // Admission evidence: counter delta across the batches. The daemon
    // drains ~100 packets/s (one per 10 ms loop tick), so right after a
    // burst the final read trails the sends: poll until the ledger stage
    // accounts every sent envelope, or a 60 s drain deadline expires.
    let deadline = Instant::now() + Duration::from_secs(60);
    let end = loop {
        let m = match read_metrics(control, token, timeout) {
            Ok(m) => m,
            Err(e) => return log.fail("metrics.final", e),
        };
        let accounted = m.inserts.saturating_sub(base.inserts)
            + m.storefull.saturating_sub(base.storefull);
        if accounted >= total_sent as u64 || Instant::now() >= deadline {
            break m;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let d_adm = end.admissions.saturating_sub(base.admissions);
    let d_ins = end.inserts.saturating_sub(base.inserts);
    let d_sf = end.storefull.saturating_sub(base.storefull);
    log = log.step(
        "volume.admission",
        format!(
            "admitted +{d_adm} | ledger_inserts +{d_ins} | storefull +{d_sf} | rejects:{}",
            reject_delta(&base, &end)
        ),
    );

    // Full ledger-stage accounting: every sent envelope either became a
    // fresh insert or a StoreFull rejection (saturation rounds included).
    if d_ins + d_sf != total_sent as u64 {
        return log.fail(
            "volume.admission",
            format!(
                "accounting gap: sent {total_sent}, inserts +{d_ins}, storefull +{d_sf} - envelopes vanished before the ledger"
            ),
        );
    }

    log.step(
        "ladder.done",
        format!("volume soak complete: {total_sent} envelopes accounted, +{d_adm} admitted"),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "bolina_intents_admitted_total 2\n\
        bolina_ctl_requests_total 7\n\
        bolina_wire_admissions_total 4\n\
        bolina_ledger_inserts_total 9\n\
        bolina_ledger_storefull_total 2\n\
        bolina_wire_rejects_total{class=\"table_full\"} 3\n";

    #[test]
    fn parse_metrics_reads_wire_counters_and_classes() {
        let m = parse_metrics(FIXTURE).unwrap();
        assert_eq!(m.admissions, 4);
        assert_eq!(m.inserts, 9);
        assert_eq!(m.storefull, 2);
        assert_eq!(m.rejects, vec![("table_full".to_string(), 3u64)]);
    }

    #[test]
    fn parse_metrics_fails_when_counters_missing() {
        assert!(parse_metrics("bolina_intents_admitted_total 2\n").is_err());
    }

    #[test]
    fn reject_delta_only_reports_growth() {
        let base = MetricsSnapshot {
            admissions: 1,
            inserts: 2,
            storefull: 0,
            rejects: vec![("table_full".into(), 3u64), ("bad_sig".into(), 7u64)],
        };
        let end = MetricsSnapshot {
            admissions: 5,
            inserts: 2,
            storefull: 1,
            rejects: vec![("table_full".into(), 6u64), ("bad_sig".into(), 7u64)],
        };
        assert_eq!(reject_delta(&base, &end), " table_full=3".to_string());
    }
}
