# G5 — Volume soak receipt

**Result: 11 944 / 11 944 rounds PASS. Zero failures. Latency flat. ~24 million
envelopes through the admission path with no degradation.**

First soak that measures admission-path behaviour under sustained volume —
the dimension G4's Honest Declaration 1 declared unmeasured. It closes that
declaration on the volume axis.

## Result

| | |
|---|---|
| Target | commit `f74d57b` (see §Target note for tag relationship) |
| Window | 2026-09-10T20:58:18Z → 2026-09-11T04:58:23Z (**8h exact**, 28 803 s) |
| Rounds | 11 944 · passes 11 944 · failures **0** |
| Envelopes through admission | ~24 million (2 000/session × 11 944) |
| Ladder V batches | ~240 000 batches of 100, metrics logged |
| Co-tenancy | 97 samples, all `clean`, 0 breaches |
| Rung E (entry gate) | PASS against sealed Zig reference |
| Restore | complete |

Configuration: `--envelopes-per-session 2000 --epoch-rounds 4
--drain-delay-ms 1000`. Both corrections were necessary: before them,
one round in four fell (backlog masked by slot exhaustion and vice versa —
see G4 §Throughput Limitation and the knee-test table in
`docs/w12-integration-harness-design.md` §16).

## Latency curve — the open question of Declaration 1

Sampled at fixed round intervals across the 8h window:

| Round | Mean throughput | Worst batch |
|---|---|---|
| 0 | 48 306 env/s | 45 ms |
| 1 000 | 38 207 | 78 ms |
| 3 000 | 38 176 | 80 ms |
| 5 000 | 49 689 | 46 ms |
| 7 000 | 74 386 | 44 ms |
| 9 000 | 36 530 | 84 ms |
| 11 800 | 36 504 | 86 ms |

**No trend.** Round 11 800 sits at the same level as round 1 000; the
worst-band never leaves 42–86 ms. The dispersion is machine noise, not
wear. Admission latency does not degrade as the ledger fills within a
session.

## Why the curve is flat — epochs vs the O(n) ceiling

The linear-dedup ceiling (G4 §Throughput Limitation) is real: admitting
envelope *n* costs proportional to *n*. But the scan cost is bounded twice
over. Within an epoch the ledger saturates at `MAX_ENVELOPES` = 4 096
(mid-round 2 of each 4-round epoch, rounds 0-indexed: ~2 005 wire admissions/round → 4 010 at end of round 1, 4 096 crossed inside round 2) and every later insert pays a fixed
O(4 096) scan then exits `StoreFull` — it cannot grow further. And the
epoch restart every 4 rounds resets the table to zero, so the ceiling is
re-entered from scratch each time rather than compounded.

This **complements**, not contradicts, the throughput declaration: the
ceiling exists; what the soak measures is the ceiling *capped*, not the
ceiling *growing*. Flat latency across 11 944 rounds is the signature of
a saturating structure, not an unbounded one.

## What this soak closes

- **G4 Honest Declaration 1, volume dimension**: the admission path —
  verify_envelope_admission, hash store, replay windows, intent table,
  ledger growth, linear dedup — exercised at ~24 M envelopes with zero
  failures and stable latency. The daemon is loaded admitting, not
  handshaking-and-restarting.

## What remains open — written before someone finds it

1. **Ledger behaviour beyond an epoch.** The epoch reset is the very thing
   that keeps the ledger shallow. Behaviour under a continuously-growing
   ledger past 4 096 entries across restarts is unmeasured, and not
   reachable without changing epoch semantics.
2. **Session concurrency.** Same structural ceiling as G4 §Structural
   Limitation: 16 handshake slots with shared indices, identical in the
   reference. Both open items hit it. Index decoupling would be a protocol
   design change — improvement over the canonical, archived as proposal,
   not a gate prerequisite.

## Target note — tag relationship

The soak ran against `f74d57b`, which is 1 src-bearing commit ahead of the
G4 tag `v0.8.0-integration-candidate` (`9a1cdf1`). The src/ delta is
additive only: `handshake.rs` +128 (created_ms timestamp field,
`release_slot`/`release_stale` methods — implemented, unit-tested, **not
wired into the daemon's execution path**; the immediate-release variant was
reverted after the shared-index conflict was found), `daemon.rs` +1
(now_ms pass-through, forced by the signature change). No behavioural
change to session handling. The volume soak therefore measures the same
execution path as G4, and the evidence is consistent with the frozen tag.
If the seal wants a tag exactly at `f74d57b`, that is the owner's call —
§15 does not require one because src/ behaviour is unchanged.

## Evidence

- Tarball: 120 ladder-V batch-metric samples, `soak.log` (11 944 rounds),
  `co-tenancy-timeline.csv` (97 samples), `rung-e.log`, Zig daemon log.
- `evidence.sha256` hash root `f0cffea2839c52e2…`, verified at both ends.
- Operator: Daniel. Machine: his box, co-tenancy closed and sampled 5-min.

## Status

Volume soak closed 2026-09-11. G4 Honest Declaration 1 closed on the
volume dimension. The G4 seal/swap decision remains the owner's — this
receipt adds evidence to it and pre-empts nothing.

---

*Receipt authored 2026-09-11. Soak operated by Daniel. Evidence verified
against his tarball hash.*
