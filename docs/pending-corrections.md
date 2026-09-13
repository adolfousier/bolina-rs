# Pending corrections (post-seal)

§15 freeze policy: corrections that surface during a soak gate are listed
here and land in the **next** candidate, after `v0.8.0-integration-candidate`
(`9a1cdf1`). src/ froze at the tag; it is unfrozen now that the G5 receipt
issued and the owner decision is registered — but everything sealed stands
as tagged, and new work moves forward, not back onto the sealed head.

## 1. Wire-path admission counters (G5 §Correction) - **LANDED** (`b859732`, `81c0228`): counters, `/metrics` exposure,
round-level accounting in the kit, V resource rotation (resolver cap `MAX_RESOURCES = 32`,
Zig parity). Remaining: Daniel's 1 h instrumented volume re-run for the G5 re-issue.

`bolina_intents_admitted_total` increments on the HTTP path only, by design
(G2 finding #1; `src/control_api.rs:230`). No wire-path counter exists, so
a volume soak cannot distinguish admitted envelopes from scan-then-`StoreFull`
rejects — the 8 h run could only bound admission by capacity arithmetic.

- Add counters on the wire path: `bolina_wire_admissions_total` (accepted
  arm of `dispatch_intent`), `bolina_wire_rejects_total` (by `VerifyError`
  class), `bolina_ledger_inserts_total`, `bolina_ledger_storefull_total`
  (in `verify_envelope_admission`).
- Extend `metrics_body` with the new series; counter names pinned in tests.
- Ladder V reads `/metrics` before and after each session and reports the
  admitted/rejected delta in the batch log line.
- Then a **1 h** instrumented re-run (same §16 flags, `--epoch-rounds 4
  --drain-delay-ms 1000 --envelopes-per-session 2000`) turns the derived
  bounds into measurements; G5 is re-issued with them.

## 2. Greedy socket-drain: THE critical path for G5 volume (owner-approved direction, 2026-09-13)

Measured chain (Daniel, 18 280-ronda G4-rerun window + raw-socket control):
`src/daemon.rs:154-162` one `recv_from` then unconditional `sleep(10ms)` →
~100 datagram/s by construction; SO_RCVBUF unset in BOTH trees; kernel
rmem_default 212992 with truesize → **227 packets max backlog** (raw control:
300×312B to unread socket → 222 delivered, 78 dropped). So the G5 floor
2+N=302 is unreachable at N=300 by buffer physics, and ~88% of the
2 000-envelope rounds died in the kernel before the daemon saw them.

Fix, one src/ commit + one tools/ commit:
- daemon: loop `recv_from` until `WouldBlock`, capped at **K=128** per tick
  (fairness bound so poll_control never starves), `sleep(10ms)` ONLY when the
  queue drained empty. K=128 because V batch inflow (~100 per few ms) exceeds
  a 64-per-tick drain; 128 gives ~12.8k/s sustained vs ~10k/s burst pacing.
- SO_RCVBUF raising is pointless below root sysctl (rmem_max == rmem_max
  default here, both 212992) → NOT part of the fix.
- ladder V: pace 10 ms between 100-envelope batches so inflow stays under
  drain rate at any N (N=2 000 would otherwise refill the buffer between
  ticks). Floor 2+N STAYS at 302 — the tripwire is the point; if it still
  trips after the drain, that is a NEW finding, not a reason to lower it.
- Verification before the window: local 2-round soak must show ledger
  arrivals == 6+N with bind+0, and the raw control on the SAME kernel must
  still show 227 (confirms the floor is the buffer, now drained).
- Zig parity note: the reference has the same one-packet-per-tick structure;
  fixing the port ahead of the frozen reference is allowed here because the
  soak contract (G5 floor) is the port's, not the reference's.


## 3. A's frozen envelope targets the vector's undeclared resource (found by
round accounting, 2026-09-12)

Round 0's frozen intent carries `bol:c3ef.../logs/deploy.log` - not declared -
so dispatch refuses it; A's admission only lands from round 1 (built path,
declared lane). The frozen round-0 envelope is a byte-exactness check, not an
admission exercise; either declare the vector resource at boot or accept the
one-refusal pattern and document it in the G5 re-issue. Small tools/ change,
no src/ touch.
