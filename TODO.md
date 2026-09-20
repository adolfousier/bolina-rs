# TODO (Huntley stage-3 driver)

Rule: ONE item "now" at a time. When done, mark [x], promote the next, `git commit`, loop.
Citations pull `file_read` back to `~/srv/zig/bolina` (original Zig tree) while implementing here.

## NOW

Queue 100% owner-gated (driver synced 2026-09-20 by bolina-continuity watchdog; the old
"DONE 30/42 / REMAINING (13)" line was stale, superseded by Corpus CLOSED below since
2026-08-27). No unsupervised src/ work until one of these lands:

1. §5 row 4 soak acceptance for the slot release (design doc §5, handshake-slot-release-design.md):
   `--epoch-rounds 20` on target WITHOUT `--allow-handshake-cap`; expect all 16 rounds pass,
   `hf+0` every round, ledger past ~1 220 walking toward 4 096. Target = mengle via orbit-ext;
   soak repo `~/srv/soak-g3-rs/bolina-rs-head` must pull tip `d6aa561` first. NOTE: no
   orbit-ext/mengle alias exists in the crab-box ssh config, so this gate is reachable only
   from Daniel's side (or after he re-provisions the alias).
2. VOL-1 / G5 1 h instrumented re-run (Daniel, mengle) → G5 re-issue with measured admission
   (pending-corrections #1 remainder).
3. Formal seal of the next candidate (Daniel; slot release was its first item and landed).
4. Reference swap + tag `frozen-reference-2026-09-14` reaching adolfousier/bolina (Adolfo,
   GitHub-visible moves gated per candidate-seal.md).

Sheet standard set by specs/render.md: public signatures, error set, invariants w/ BE-* links,
test-semantics checklist as future asserts, file:line citations only (never "the spec in general").
No sheet, no wave. After each batch: push, tick LOGBOOK.

## Waves

- [x] W0 workspace + strict lints + ReleaseSafe-parity profile (969a812)
- [x] W1 crypto head, crates per D-096-A pinned; 6 RFC KATs green; first lastro receipt
  issued+VERIFIED (34272ae, docs/receipts/w1/)
- [x] W2 codec byte-for-byte vs frozen test/vectors.json (8/8, negatives included);
  BE-SIG-01 composition assert pinned by vector sig_input_hex
- [x] W3 intent table + grant ledger durable two-phase I/O (flock via seam); 21/21 tests;
  restart-replays-exact-state caught a real port bug (recover() EOF re-read)
- [x] W4 Noise_IK + handshake + binding; G2 ladder A/B/C live interop vs the Zig daemon;
  IK pre-message (responder static mixed into h) fixed after the ladder caught it
- [x] W5 session/relay/reassembly/sync + main + control-plane HTTP CLOSED
  (876 lines, 47 tests; LOGBOOK 2026-08-28)
- [x] W6 ca CLI (init/issue/list/show/revoke, v3 always F15, subject-expiry BE-CTRL-03)
  + keys (052e3ae)
- [x] W7-W11 parity waves per D-097 sheets (LOGBOOK 2026-09-05..07): W7 authority, W8 audit,
  W9 support, W10 complete (mutation 43/43, suite 319/0), W11 closure (mutation 49/49,
  suite 375/375)
- [x] W12 task-8 daemon wiring (handshake msg2 -> binding -> sig gate -> F5 admission -> dispatch/EventRing -> control API/SSE; keys::load_or_generate at boot; 10 named tests in tests/w12_daemon.rs) + task-9 mutation closure 47/47 killed, lastro receipt docs/receipts/w12/ (W7-W11 closures: see LOGBOOK)
- [x] Post-seal candidate item #1: handshake slot release (b6f1dd6, idle sweep T_HS_IDLE_MS,
  three-structure release, metrics released_total/slots_used; mutation 69/69; closeout d6aa561).
  Its §5 row 4 soak acceptance stays OPEN as NOW item 1.

## Unbreakable rules

1. NO swap of reference head until W6 parity + new full battery (mutation domains, cross-diff
   Zig-vs-Rust, re-soak on owner's box) + owner's explicit declaration (D-096).
2. Bugfixes land in Zig FIRST while it stays reference; sheet updated same commit; wave absorbs.
3. Bytes are built field-by-field; no transmute/as_bytes of protocol structs (E2).
4. No async runtime (tokio et al) until post-swap review (E4); mirror the single-threaded poll design.
5. Every gate crossed gets a lastro receipt where feasible and one LOGBOOK line (signal, no noise).

## Corpus CLOSED (33 sheets, 2026-08-27)

Sheets done: all production modules; EXCLUDED deliberately (not sheets): `*_test.zig` (become
the named Rust test suites per sheet), `cert_test_helpers.zig`, fuzz roots, `gen_vectors`. Counter claim of "42" counted test files; REAL production targets = 34.
