# Stage-2 contract sheet: `dispatch.zig` (352 lines)

Zig source: `src/dispatch.zig` @ bolina main (`d24cf74`). Tests: `src/dispatch_test.zig`
(975 lines, 20 named tests). Wave target: **W3/W5 seam** (needs W2 codec + W3 ledger).
BE anchors: BE-GRANT-01/01a/03/04, BE-EXEC-02, D-062/D-064 R1, F13, F16.

## Contract

The router. One envelope in -> ONE of seven outcomes out, with every state
mutation ordered exactly here and nowhere else:
admission runs through the SAME `resolveAndAdmit` the wire uses (no god-mode
side door), grants execute through `verifyGrantThen`, the durable consumed-grant
ledger owns replay refusal, and effects fire EXACTLY ONCE inside the verify call.
Module-level seams (module-level because hooks are bare fn pointers, M10 shape):
`durable_ledger` singleton + optional `control_events` ring (D-091 P2; null on
wire-only builds = zero hot-path cost beyond one null check per commit).

## Error set (line 46)

`BadEnvelope` · `BadBody` · `UnsupportedBody` · `NoPendingIntent` ·
`UnknownSender` · `ActionTooLarge` · `DiskError` (F4 ledger I/O).
dispatch() returns the union with `verify.VerifyError || resolver.ResolveError ||
intent.IntentError` — Rust maps this to ONE flat enum at the boundary.

## Outcome enum (line 56, exhaustive — never collapse variants)

`intent_admitted` · `grant_executed` (effect fired once INSIDE verifyGrantThen) ·
`effect_refused` (checks passed, commit durable, executor declined =
**unpublished orphan**, BE-GRANT-01a brief 9.1) · `refusal_applied` ·
`utterance` · `control` · `effect`.

## Hooks (line 66)

```zig
execute_effect: fn(channel.Grant) verify.EffectOutcome,
cert_for_sender: fn(sender []u8) ?session.Cert,
on_rejected: fn(intent_id []u8) void,
```

## Public surface

| Item | Signature | Notes |
|---|---|---|
| `attachEvents` | `(ring *EventRing) void` | module-level ring (line 95) |
| `initDurableLedger` | `(io, path, orphan_out []Orphan) !usize` | opens + recovers, COPIES orphans into caller slice (deliberate: Recovery borrows internal buf while tombstoneOrphan mutates); ResourceExhausted if list cap exceeded (line 99) |
| `closeDurableLedger` | `() void` | |
| `seamBreakLedgerWrites` | `(io) void` | TEST-ONLY failure injection (line 126); must remain invisible to prod config |
| `tombstoneOrphan` | `(grant_id[16]) !void` | |
| `Dispatch.init` | `(resolver, own_pubkey, own_cert, trusted_ca_keys) Dispatch` (line 190) |
| `Dispatch.dispatch` | `(*self, env Envelope, hooks Hooks, now_ms u64)!Outcome` (line 206) |

## Invariants (each has its named test; port ALL, keep ORDER)

1. **Intent admission routes through resolveAndAdmit; canonical resource lock
   held** (DAEMON_A line 155). Unknown resource refuses at seam, table untouched
   (line 171).
2. **Restart expires pending approvals BY CONSTRUCTION** (BE-GRANT_04,
   test line 647): pending lives only in RAM intent table, never committed.
3. **Grant naming no pending intent refuses with NoPendingIntent; no service**
   (line 181). Effect fires once inside the frame; replay refused by state
   (DAEMON_D line 475).
4. **Reused grant_id refuses EVEN against a fresh intent** (ledger answer wins,
   line 512); commit row AND publish tombstone both hit disk after the effect
   (line 542).
5. **Refused effect leaves a durable unpublished orphan** (line 571); crash
   residue surfaces one orphan, tombstone retires it (line 682).
6. **Fail-safe: no durable ledger = grant REFUSED before the effect**
   (D-064 ruling 1, test line 942). Never run effects un-ledgered.
7. **Revoked approver / revoked subject refuse at checks 3-4 / 4**
   (BE_REV_02 wired, lines 836/892).
8. **Refusal happy path**: pending moved to REJECTED inside frame, on_rejected
   fired exactly once (line 775). Bad envelope signature refused at the
   structural gate (line 804). Bad body for declared type refuses (line 236).
9. **Sender-record storage bound is executor-scoped, not wire ceiling**
   (F13, line 964).
10. **HTTP-admitted intents execute via wire grants** (F16 composition,
    line 420): admitted via control plane WITHOUT a sender record -> later
    grant hits UnknownSender -> refused (this was finding F16; subject binding
    fixed it Zig-side; Rust inherits the fix shape).

## Rust acceptance gate (W3 seam tests)

The 20 tests port as an integration suite driving Dispatch with fake hooks +
temp-dir ledger; outcome enum exhaustively matched (compiler-enforced);
`seamBreakLedgerWrites` becomes a test-only constructor knob, not a global.
Effect-fired-exactly-once is asserted via hook counter == 1 in all three of
happy/refuse/orphan paths.
