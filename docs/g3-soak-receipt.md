# G3 Soak Receipt — v0.7.0-candidate

> **Evidence gate for seal/swap decision.** This document summarises the Run 3 soak evidence and provides the basis for the owner's seal and swap decision.

## Target

| Field | Value |
|---|---|
| Tag | `v0.7.0-candidate` (annotated `33a8872`) |
| Commit | `be8f658` |
| Description | Full port parity (W1-W11, 49/49 mutation, 373/0 tests at soak time, 830+ lines gap closure) |

## Soak Window

| Field | Value |
|---|---|
| Start | 2026-09-06T16:50:20Z |
| End | 2026-09-07T16:50:24Z |
| Duration | **24h continuous** |
| Workers | 4 @ 50M inputs/seed |
| Machine | Daniel's Linux box (co-tenancy verified) |

## Results

| Metric | Value |
|---|---|
| Rounds | **2,964** |
| Failures | **0** (`failures.log` = 0 bytes) |
| Tests executed | **1,105,572** (373 per round, proven in log) |
| Cross-diff 6/6 | **2,964 / 2,964** (100%) |
| Chaos invocations | 11,856 (4 workers × ~2,964 rounds) |
| Co-tenancy samples | 288/288 `clean` (0 breaches, 5-min sampling) |
| Thermal samples | 2,880 (131 above high of 86°C, max 95°C) |
| Kernel thermal events | **0** (zero throttling) |
| Evidence files | 2,979 hashed, 353 MB (tarball 65 MB) |
| Evidence SHA | `b4497654f269f6c7…` |

## What This Run Validates vs Runs 1-2

| Aspect | Run 1-2 | Run 3 (G3) |
|---|---|---|
| Code surface | 3,165 lines (wire path only) | **7,757 lines** (full port) |
| Tests per round | 174 | **373** |
| New modules under load | none | verify, dispatch, resolver, envelope admission, evidence, dag |
| Co-tenancy proof | snapshot or 4h30 | **24h continuous sampling** |
| Load | ~0.35 (idle) | **~4** (real pressure) |

## Anomaly T3 — Final Status

The T3 anomaly (round 562, Run 2) did **not** reappear.

| Metric | Value |
|---|---|
| Occurrences | 1 (round 562, Run 2) |
| Equivalent rounds | 16,515 (13,551 hunt + 2,964 G3) |
| Total exposure | ~64,000 rounds across two regimes |
| Upper bound @ 95% | **<1/5,500** (rule of three) |
| Hypotheses eliminated | 5 (by experiment) |
| Forensic instrumentation | armed, never triggered |
| Code identity | `ledger.rs` and `tests/state.rs` byte-identical between `e24c839` and `be8f658` |

The citable number is the upper bound, not the point rate.

## Honest Declarations

### Thermal Peak

131/2,880 samples above the 86°C high watermark, peak 95°C at 22:19Z. The kernel logged zero thermal or throttling events, and the run completed without interruption. The checklist accepts throttling ("slower run, declared in receipt") — only thermal shutdown would invalidate. **No invalidation.**

### Evidence Scatter

Evidence was initially written to two directories due to a wrapper bug (SOAK_LOG_DIR not passed to pause/restore phases). All 8 displaced files were recovered into the run directory and the `evidence.sha256` was re-signed (2,979 entries). **Nothing was lost.** Dates on displaced files may differ from the run window.

## Suite Evolution Since Soak

The soak ran with **373 tests/round**. Since then, the cron watcher identified and closed a real BE-LEDGER-01 mutation survivor (partial-parents gap), adding 2 literal tests. Current suite: **375 passed / 0 failed**. The 2 additional tests exercise the same ledger code that ran in every G3 round.

## Pre-existing Drift (Documented, Not Fixed)

| Item | Status |
|---|---|
| `cargo fmt` drift | 58 files (toolchain 1.98, no historical gate) |
| `cargo clippy` style lints | 41 (under `deny(warnings)`) |
| Decision | Pending owner — gate fmt/clippy in repo or accept drift |

This drift is cosmetic and does not affect correctness, mutation coverage, or soak results.

## Residual Items (Declared, Not Blocking)

1. **Daemon wiring HTTP→control_api** — the `/v1` module exists and is tested; not wired to the daemon server
2. **SSE/counter byte-compare vs Zig** — spelling pinned in Rust tests; byte-compare needs Zig tree on owner's machine

Neither blocks seal parity — they are post-port integration work.

## Seal Recommendation

The evidence supports sealing `v0.7.0-candidate` (`be8f658`) as the reference Rust port:

| Gate | Verdict |
|---|---|
| Suite (373→375/0) | ✅ pass |
| Mutation (49/49 KILLED) | ✅ pass |
| Soak (24h, 2,964 rounds, 0 failures) | ✅ pass |
| Cross-diff (6/6 × 2,964) | ✅ pass |
| Co-tenancy (288/288 clean) | ✅ pass |
| T3 anomaly (<1/5,500 @ 95%) | ✅ acceptable |
| Thermal (no kernel events) | ✅ acceptable |
| Audit (33 sheets, item-by-item) | ✅ pass |

**Seal and swap are the owner's decision, with this evidence on the table.**
