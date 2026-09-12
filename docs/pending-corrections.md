# Pending corrections (post-seal)

§15 freeze policy: corrections that surface during a soak gate are listed
here and land in the **next** candidate, after `v0.8.0-integration-candidate`
(`9a1cdf1`). src/ froze at the tag; it is unfrozen now that the G5 receipt
issued and the owner decision is registered — but everything sealed stands
as tagged, and new work moves forward, not back onto the sealed head.

## 1. Wire-path admission counters (G5 §Correction)

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
