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

Fix, one src/ commit + one tools/ commit. K semantics RESOLVED 2026-09-13
after the owner caught the contradiction (regime said sleep-only-on-idle while
the justification treated K as K×100/s throughput):
- daemon: loop `recv_from` until `WouldBlock`; K caps datagrams PER PASS
  before poll_control gets its turn, and there is NO sleep while the queue
  is non-empty. Throughput is therefore CPU-bound (ed25519 verify dominates,
  ~20-50k/s); K is ONLY a fairness bound on control-plane latency.
- K=64 chosen. It is not a capacity knob (128 vs 64 differ by nothing at
  steady state); it is worst-case wait before poll_control: 64 packets ≈
  64 verify-times ≈ 1-6 ms of HTTP/SSE starvation. Smaller cap = fairer.
  The old "6400/s" arithmetic belonged to the sleep-always regime and is
  retired here.
- Consequence, stated flatly: a burst at full send rate outpaces any
  single-core drain no matter the cadence. OWNER KERNEL DATA (2026-09-13,
  separate-process sender/receiver, 312 B, busy-read receiver with
  emulated per-packet cost): a 300-burst WITHOUT pacing survives only
  below ~5 µs/packet of drain cost; at 10-30 µs it delivers 248-261,
  78-52 die in the kernel. The verify-dominated estimate here (20-50k/s)
  is 2-5× SHORT of the >100k/s a 300-burst needs. The earlier prediction
  that drain alone would make a 300-round land 300/300 is FALSIFIED by
  that measurement and RETIRED: at ~300k/s emission and ~33k/s drain the
  peak backlog is ~267 > 227, exactly the measured band, and the 25 µs
  point reproduced 227 — the model holds, the conclusion drawn from it
  did not.
- Lossless volume therefore REQUIRES client pacing at N=300 TOO, not only
  at N=2 000 (owner correction, adopted): ≤100 envelopes per 10 ms.
  Paced receipts measured on the same kernel: 300 at 20/30/50 µs and
  2 000 at 20/30 µs → all delivered in full, zero loss across the range.
- Acceptance, per owner (2026-09-13): "300/300 with drain AND pacing" —
  drain alone is necessary and insufficient. The measurement suite must
  include a no-pacing case that FAILS, or the two parts cannot be
  attributed. Measure drain cost with a LOADED ledger (≥200 entries):
  envelope-ledger dedup is a linear scan up to MAX_ENVELOPES=4096, so
  per-packet cost grows as the round fills — the drain is slowest exactly
  when the backlog is largest. The owner's sender was Python (160-310k/s);
  a Rust burst client is faster, so the unpaced case is worse than
  measured, not better.
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
- **Ledger-loaded measurement DONE 2026-09-14** (this machine, 16×300,
  epoch_rounds=20): the required observation could not reach the ledger —
  the 16-slot handshake table fills at round 4 (4 wire handshakes/round)
  and every wire ladder dies at msg2 (bind/trp/prs=0, hadm+1 alive).
  Ledger peaked ~1220 live; latency FLAT rounds 0-3 (48-68ms/300-env).
  The 4096 scan cost is answered deterministically instead
  (tests/w14_ledger_sizing.rs times BOTH terms at cap — insert-dedup
  and the dominant all_parents_present with 8 worst-case parents;
  target worst case 5.5µs + 46.4µs ≈ 54µs vs the 100µs pacing budget,
  ~2x margin, verify/fsync excluded. The first version of this note
  quoted only the dedup term; Daniel's target measurement showed the
  parent-check is the dominant one).
  HandshakeFull is now a counted reject class and the wrapper guards
  epoch_rounds past the wall (--allow-handshake-cap). See G5 receipt
  corrigendum 2026-09-14.


## 3. A's frozen envelope targets the vector's undeclared resource (found by
round accounting, 2026-09-12) - **CLOSED as documented** (2026-09-15, verdict below)

Round 0's frozen intent carries `bol:c3ef.../logs/deploy.log` - not declared -
so dispatch refuses it; A's admission only lands from round 1 (built path,
declared lane). The frozen round-0 envelope is a byte-exactness check, not an
admission exercise; either declare the vector resource at boot or accept the
one-refusal pattern and document it in the G5 re-issue. Small tools/ change,
no src/ touch.

**Verdict, measured 2026-09-15: CLOSED as documented.** "Declare the vector
resource at boot" cannot work. `Resolver::resolve` checks the embedded
executor fp AFTER membership (resolver.rs:260): a declared
`bol:c3ef.../logs/deploy.log` flips from `UnknownResource` to
`ForeignExecutor`, still refused, because the daemon's sig key is generated
per boot (boot evidence, same box: `33f0b22d...` then `705cb056...`; run fp
`8572dcd9...` ≠ vector fp `c3ef...`). The design doc already states the rule
(§5.1.4: "for the daemon to resolve this resource locally, it must **be**
that executor") - round 0's one-refusal is that gate working, not a wiring
gap. The refusal is NOT silent: dispatch's Err arm bumps
`WireRejectClass::from(DispatchError)` (daemon.rs:543-546) into the counted
`r_unknown_resource` class. What was wrong was §5.3's table, which promised
"epoch round 0 expects the same counts" - six wire admissions are
arithmetically impossible there; real rounds land 5 + the counted refusal,
and no wrapper gate enforces the per-ladder totals (the floor is V-only), so
the design claim drifted from observation unnoticed. Table fixed in §5.3;
the positive half of the executor-binding check stays rung E's job (the
vector resolves only against its own executor, i.e. the Zig daemon
provisioned with the vector key).
