# G4 Integration Soak Receipt

**Date:** 2026-09-09
**Target:** `v0.8.0-integration-candidate` → commit `9a1cdf1`
**Window:** 2026-09-09T14:56:58Z → 17:57:01Z (3h 00m 03s, 10,803 s)
**Operator:** Daniel (@iamloonix)
**Machine:** Linux (same box as G3)

## Result

| Metric | Value |
|---|---|
| Rounds | 25,689 |
| Passes | 25,689 |
| Failures | 0 |
| Rung E (entry gate) | PASS vs Zig v0.6.1-13-g9447ca8 |
| Co-tenancy | 37/37 clean, 0 breaches |
| Machine load | ~0.5, 36 °C |
| Restore | complete — services and crontab restored |

Each round exercises four ladders (A/B/C/D) against the running daemon, with
EPOCH_ROUNDS=5 and daemon restart to rearm the 16-slot handshake table.

## Scope

This is the **first evidence on the integrated daemon** — not on isolated
modules. The G3 soak (24h, 2,964 rounds, 1.1M tests via `cargo test`)
exercised modules in isolation; at that time the daemon did not even import
the authority layer. This soak exercises the integrated path: verify,
dispatch, resolver, and envelope admission in the daemon's execution path,
with real traffic entering.

The four ladders cover:

| Ladder | Path |
|---|---|
| A (Happy Path) | handshake → binding → 3 envelopes (intent, grant, effect) |
| B (Refusal) | expired grant → refusal verified |
| C (Rejection) | frozen intent + idempotent dup + transport replay + truncated + sig-patched |
| D (Control API) | POST /v1/intents (202/202/422/400) + SSE GET /v1/events |

Rung E runs once as the entry gate: handshake + binding + frozen envelope
against the Zig reference daemon. Cross-verified in both directions (client
opens daemon's binding frame, verifies sig over 0x05||h against the
provisioned executor; transcript hash byte-identical).

## Honest Declarations

### 1. This soak does NOT measure sustained load

Load ~0.5, 36 °C. It measures correctness of the integrated path. Sustained
load comes from G3 — 24h, load ~4, peak 95 °C — over modules. The two pieces
are complementary and neither substitutes the other.

### 2. This soak does NOT measure process longevity

The handshake table has 16 slots and neither implementation frees them, so
EPOCH_ROUNDS=5 and the daemon restarts every five rounds. The 25,689 rounds
are ~5,000 short epochs, not one process living three hours. Memory leaks or
state degradation over time remain unmeasured. Closing them requires changes
to the reference, not just the port.

### 3. Wire-path admissions are invisible to SSE and /metrics

Per §5.1.4 delta 1: the reference publishes grant lifecycle events and
HTTP-admitted intents to the EventRing, not wire admissions. The observable
channel for a wire admission is `GET /v1/intents/<32hex>` → 200 `pending`.
This is reference behavior (the Zig daemon discards `_ = handleDatagram`
outcomes), not a port gap.

### 4. Rung E ran against v0.6.1-13-g9447ca8, not the v0.6.1 tag

Per §5.1.2: the v0.6.1 tag lacks `link_libc` (never compiled on Linux;
f55c4b5) and carries the type-2 handshake index bug fixed by e4fd0d4, which
the Rust port already conforms to. Wire-identical to the port's verification
reference (v0.6.1-18-g53fd099, docs-only delta).

## Anomaly T3 (cross-gate)

The T3 anomaly (G3-run2, round 562) traverses both gates:

| Metric | Value |
|---|---|
| Occurrence | single, round 562 of G3-run2 |
| Equivalent rounds | 16,515 (4 workers, 50M inputs) |
| Upper bound (95%) | <1/5,500 (rule of three) |
| Total exposure | ~64,000 rounds across two regimes |
| Reproduced | never |
| Hypotheses eliminated | 5 (by experiment) |
| Forensic instrumentation | armed, never fired |

The `ledger.rs` and `tests/state.rs` are byte-identical between e24c839 and
9a1cdf1, so T3 runs inside every round of both G3 and G4. The upper bound
is the citable number — not the point rate.

## Evidence

7 artefacts, hashes verified at both ends:

| File | Description |
|---|---|
| soak.log | 1.2 MB, round-by-round pass/fail log |
| round-logs.tar.gz | 102,761 per-round per-ladder logs (3.2 MB compressed, 403 MB raw) |
| co-tenancy-timeline.csv | 37 samples, all clean |
| rung-e.log | Rung E entry gate log (PASS, exit 0) |
| zig-daemon.log | Zig reference daemon log |
| daemon.log | Rust daemon log |
| daemon-boot1.log | Rust daemon first-boot log |
| evidence.sha256 | SHA-256 of all evidence files (excluding daemon-data/ key material) |

## Tag

`v0.8.0-integration-candidate` → `9a1cdf1` (pushed).
Source frozen per §15 from this tag onward.

## What This Receipt Does NOT Cover

- Sustained load (covered by G3 receipt)
- Process longevity beyond 5-round epochs
- Wire admission visibility in SSE (reference behavior, §5.1.4 delta 1)

## Seal Decision

**Date:** 2026-09-09
**Decision:** Daniel (@iamloonix) seals `v0.8.0-integration-candidate` (commit
`9a1cdf1`) as the integration reference head for the bolina Rust port.

**Evidence reviewed:**
- G4 soak: 25,689/25,689 rounds PASS, 3h, four ladders against running daemon
- Rung E: PASS against Zig v0.6.1-13-g9447ca8 (cross-verified bidirectionally)
- Co-tenancy: 37/37 clean
- Four honest declarations accepted
- Anomaly T3: cross-gate, <1/5,500 @ 95%, not reproduced in ~64,000 rounds
- Kit corrections (evidence.sha256, log volume, --outdir) verified

**Swap:** The Rust port at `9a1cdf1` is now the integration reference. The
Zig reference (v0.6.1-13-g9447ca8) remains the original specification. Future
work builds on top of this head.

**Authority:** D-096 (seal/swap decision is the owner's call).

---

*Receipt authored 2026-09-09. Soak operated by Daniel. Evidence archived. Sealed 2026-09-09.*
