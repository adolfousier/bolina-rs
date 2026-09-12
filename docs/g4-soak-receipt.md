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

Each round exercised ladders B/C/D against the running daemon; A's binding was unframed and dropped (see Correction 2026-09-12), with
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

## Correction (2026-09-12): Ladder A Never Bound - G4 Requires Re-run

Post-seal wire counters exposed a client-side defect in the code this gate ran
on. At `9a1cdf1`, `ladder_a.rs` built the binding frame inline without the
`u16be(cert_len)` prefix (the local `cert_len` existed only for the log line);
the daemon parses the prefix strictly and dropped the frame silently - so
**every envelope of ladder A was lost in all 25,689 rounds**. Verified at the
sealed commit itself, not inferred:

| Ladder | Binding path at 9a1cdf1 | State |
|---|---|---|
| A | `ladder_a.rs:247` exchange + inline unframed frame | **broken** - never bound |
| B | `ladder_b.rs:74` `open_bound_session` (framed shared path) | intact |
| C | `ladder_c.rs:44` `open_bound_session` - the zero `cert_len` occurrences in C mean C never built the frame by hand, which is precisely why C was fine | intact |
| D | HTTP path | unaffected |

So the integrated admission path was exercised by B/C/D, not by the four
ladders the table above claims. The counters, framed bindings, drain
accounting and per-round `/metrics` equality (`binding_delta == 0` as the
unframed-binding tripwire) landed in `b859732`+. An instrumented G4 re-run on
the fixed client supersedes the numbers claimed here. The recorded owner
decision (2026-09-11) predates this finding; re-verification was requested by
the owner on 2026-09-12 - this receipt documents the defect and does not
restate the decision either way.

## Structural Limitation: Session Concurrency

The 16-slot handshake table ceiling constrains concurrent sessions, not
envelope volume. The Zig reference has the same ceiling with the same
absence of slot release (handshake.zig:25). This is not a port gap — it is
fidelity to the reference.

Decoupling handshake slot indices from transport session indices would
enable concurrent sessions beyond 16, but this would be an improvement
over the canonical implementation, not a conformance fix. It is archived
as a proposal for future decision, not a gate prerequisite.

The volume soak (W13, ladder V) exercises the dimension that matters:
envelope throughput within a single established session, which is not
constrained by the 16-slot table.

## Throughput Limitation: Linear Dedup (Structural, Shared with Reference)

Envelope admission uses O(n) linear dedup per insertion. Admitting envelope
n costs proportionally to n. The `--drain-delay-ms` gives the single-threaded
daemon time to drain the processing backlog before the next round; it does
not remove this structural ceiling.

This is fidelity to the reference: `ledger.zig:139-149` performs the same
linear scan over an array of 4,096 with the same `MAX_ENVELOPES` and the
same `StoreFull` behaviour. The Zig comment explains why — the scan detects
equivocation (BE-ENV-05), not only duplicates. A hash index would change
the semantics, not just the performance.

The volume soak exercised the admission path against the declared
ceilings — 256 intents/session (MAX_PENDING) and 4 096 ledger entries
(MAX_ENVELOPES) — and measured what they cost: flat batch latency,
because the ceilings cap the linear cost inside an epoch rather than let
it grow (G5 §Why the curve is flat).

## Status

Receipt authored 2026-09-09. Evidence archived.
Volume soak closed 2026-09-11: 11 944 / 11 944 rounds, zero failures,
flat admission latency across 8h — see `docs/g5-volume-soak-receipt.md`.
Honest Declaration 1 is closed on the volume dimension; what stays open
(ledger beyond an epoch, session concurrency) is enumerated in G5. Note:
the 8 h volume soak is capped at send-throughput; admitted-vs-sent awaits
the instrumented re-run (G5 §Correction).

**Owner decision — seal and swap (registered 2026-09-11).** Daniel
(@iamloonix), holder of this decision per D-096, confirmed in the project
group at 00:18 UTC:

> selo e swap claro confirmo

Scope, as agreed in that thread:

- **Seal**: `v0.8.0-integration-candidate` (annotated tag on `9a1cdf1`).
  Measured sha for this gate: `f74d57b` — the delta over the tag is
  additive and not wired (release methods + one `now_ms` pass-through,
  callers in tests only); behaviour identical. No extra tag required
  (owner's call, 2026-09-11).
- **Swap**: the Rust port at this head is now the integration reference;
  the Zig reference (`v0.6.1-13-g9447ca8`) remains the original
  specification.
- **Follow-on (does not block the seal)**: wire-admission counters plus a
  1 h instrumented re-run close the G5 §Correction gap — specified in
  `docs/pending-corrections.md`, landing in the next candidate.

---

*Receipt authored 2026-09-09. Soak operated by Daniel. Evidence archived.*
