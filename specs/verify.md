# Spec: verify.zig (the authority decision core)

> Source: `~/srv/zig/bolina/src/verify.zig` (711 lines) · tests: `src/verify_test.zig` (61 named tests).
> Rust home: `src/transport/verify.rs` (+ siblings if caps demand a split; never squeeze logic, D-F2).

## Contract summary

All authority decisions live here as pure functions over parsed wire types:
envelope signature (`BE-ENV-02`), the full grant chain (`BE-GRANT-03`, checks 0-11
in normative order), refusals, control-channel genesis/membership, mesh served-cert,
and admission gating. **Zero heap** across all of it. The routine does NOT hand back
a capability: it runs the checks, commits the ledger (check 11), and invokes the
effect itself inside its own frame (`src/verify.zig:21-22`).

## Public surface

| Zig | Line | Rust shape |
|---|---|---|
| `VerifyError` | :53 | enum, one variant per failed BE check, names IDENTICAL |
| `verifySigned(tag, tbs, sig, pubkey)` | :87 | domain-tag preprend + Ed25519 verify (`BE-SIG-01`) |
| `verifyEnvelope(env)` | :106 | envelope sender-sig wrapper |
| `actionDigest(action)` | :114 | BLAKE2s -> `[LEN_ACTION_DIGEST]u8` |
| `GrantContext` | :149 | ctx bundle incl. trusted CA set + tables + now_ms |
| `SenderTable` / `.lookup(intent_id)` | :188/:207 | map intent_id -> Entry, MAX_ACTION=512 (:194) |
| `EffectOutcome` | :239 | enum, EXHAUSTIVE in Rust (compiler-guarded: adding an outcome must break every match) |
| `verifyGrantThen(env, grant, ctx, execute)` | :244 | THE function: `Result<EffectOutcome, VerifyError>` with callback |
| `RefusalContext` / `verifyRefusalThen` | :367/:381 | mirror of grant path for refusals |
| `ChannelError`, `verifyControlGenesis`, `verifyControl` | :425/:481/:506 | control channel chain (version byte == 1; only Grant carries version==2 convention) |
| `requireMember` | :526 | mesh membership vs trusted anchors |
| `MeshError`, `SessionKeys`, `MeshContext`, `verifyServedCertThen` | :571-:595 | relay serve-cert path |
| `AdmissionContext`, `bodyTypeAllowed(bt, role_bits)` | :626/:635 | role-gated body-type admission matrix |
| `revokePruneExpiry(body)` | :655 | BE-CTRL-03 subject-expiry extraction; absent body => u64::MAX (never prune, fail-closed, F10/D-090) |
| `verifyEnvelopeAdmission(...)` | :661 | parents-before-seq (F5): allParentsPresent precedes seq-window consume |

## Invariants (port MUST preserve, each will get its own test)

1. **Check order is the contract.** `VerifyError` order at :53-70 IS normative: BadVersion(0),
   BadEnvelopeBinding(1), BadSignature(2), BadApproverCert(3)/BadSubjectCert(4),
   ApproverRevoked/OutOfScope(3a/4a), WrongExecutor(5), WrongSubject(6), NoMatchingIntent(7),
   WrongResource(8), ActionDigestMismatch(9), Expired(10), AlreadyConsumed(11).
   First failing check returns; tests assert the REASON per check.
   Test: `TestGrantChainRefusals` parity in Go head (lastro repo) already encodes this ladder.
2. **F13 state binding**: grant-chain checks 6-9 bind to records the routine fetches ITSELF
   via `matchForGrant` + `sender_table.lookup` (:258-260), never caller-assembled values.
3. **Version gate**: `grant.version != 2` => BadVersion (:252, RED-TEAM-08 F6 "field is read").
   Cert-scope checks 3a/4a run only when `cert.version >= 3`; since F15 fix the issuer emits
   v3 ALWAYS (empty scopes = deny-all) - Rust verifier keeps the same gate; a v2 cert must fail
   scope at a DIFFERENT point than silently skipping it, iff tests demand: pin with test
   `scope_v3_denyall_empty`.
4. **Expiry triad** via `checkExpiry(not_after, now, first_receipt, t_max_s, t_recv_s)` (:130):
   cert not_after OR t_max from now OR t_recv-anchored window - whichever first, Expired.
   first_receipt comes from durable ledger TAG_FIRST_RECEIPT rows (dispatch spec).
5. **Ledger commit INSIDE verifyGrantThen** after check 10, before effect (:21-24 comment):
   orphan-recovery semantics (effect failure still consumes the grant) are observable.
   Rust: same call ordering; effect callback invoked once, synchronously.
6. **No-heap**: decision paths allocate nothing; Rust naturally holds this, but forbid
   any `Vec`/`String` return from these fns (slices/borrow or fixed arrays only).
7. **Streaming sig verify** at :32: stdlib Ed25519 streaming chunking - the bound frame
   signs `0x05 || h` in chunks matching the streaming verifier's tag-then-tbs. Port uses
   dalek bulk verify over assembled bytes; KAT pins equality of accepted/rejected verdicts.
8. **Trace hooks**: grant_trace emits exist for ordering forensics; optional in Rust but
   if present must be no-op-off by default and never allocate under hot path.

## Checklist of tests to reproduce (from verify_test.zig, 61)

Core ladder: happy grant executes once · each check refusal w/ exact error (12+ cases) ·
approver/subject revoked durably · wrong executor/self-subject · scope covering/sibling/
empty-deny-all (D-085/F15) · envelope body_type mismatch · action digest mismatch ·
expiry triad branches (cert/max/window) · first-receipt anchor replay idempotent ·
already-consumed via ledger · refusal path symmetric · control genesis reject wrong quorum/version ·
member ok/not-member/quorum-no · served-cert ok/untrusted/expired · admission matrix rows ·
revokePruneExpiry absent-body => MAX / present => value · parents-before-seq gap refused.
Exact names/lines: see verify_test.zig greps at build time; Rust names carry `_parity` suffix
plus number so ratchet can diff ladders against the Go head's 12-check driver.

## Where Rust will deviate (declared, tested either way)

- Errors: single `thiserror` enum mirroring Zig names 1:1 (D-049 analog), no boxing.
- Callback: `impl FnOnce(&Grant) -> EffectOutcome` passed by value; panic in callback =
  process abort semantics equivalent to Zig panic (fail-closed node death).
