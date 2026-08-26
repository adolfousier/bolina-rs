# Stage-2 contract sheet: intent.zig

Source of truth: `~/srv/zig/bolina/src/intent.zig` (216 lines) + `src/intent_test.zig` (11 tests).
Rust target module: `crates/bolina/src/intent.rs` (W3).

## Purpose

Pending-intent pool: admission with dedup + resource exclusivity, timeout expiry,
grant matching, refusal application, execution transition. SPEC BE-GRANT-04/06/06a/09/10.
MD4 compaction semantics are part of the contract (history: 2026-08-22, commit 654a4af).

## Constants

| Const | Value | Line | Note |
|---|---|---|---|
| T_PENDING_MS | 900_000 | intent.zig:45 | BE-GRANT-06a default 900s |
| MAX_PENDING | 256 | intent.zig:46 | overflow is a refusal, not a grow |

## Errors and enums

- `IntentError` :52 - closed set. Must include capacity/duplicate/conflict variants
  mirroring Zig's; no catch-all in Rust port.
- `RefusalOutcome` enum :63 (matched / unmatched outcomes feed BE-GRANT-09 events).
- `State` enum :72 (pending -> executing -> terminal).
- `Entry` struct :84.

## Public API

- `Table.init()` :100
- `admit(intent, now_ms) IntentError!void` :112
- `matchForGrant(intent_id) ?usize` :131
- `beginExecuting(idx) IntentError!void` :136
- `applyRefusal(refusal) RefusalOutcome` :148
- `expireTimeouts(now_ms) usize` :160  (returns collapsed count)

## Invariants (each = Rust test)

1. **Fresh table holds NO pending state** (BE_GRANT_04): restart collapses ambitions
   [intent_test.zig:36]. Rust: `new()` must produce empty table; a "restore" path is
   FORBIDDEN by this invariant unless dispatch re-admits.
2. **Duplicate intent_id refused** (BE_GRANT_06b) [intent_test.zig:51].
3. **Second intent on a held resource refused** (BE_GRANT_06) [intent_test.zig:61].
   Exclusivity key = canonical resource id (dispatch sheet cross-ref).
4. **T_pending expiry releases the lock AND the slot** (BE_GRANT_06a)
   [intent_test.zig:75]: after expireTimeouts(now + T), resource is admit-able again.
5. **Matched refusal rejects pending; unmatched refusal dropped silently**
   (BE_GRANT_09) [intent_test.zig:97 / :110] - but outcome enum records which happened.
6. **Rejected cannot re-enter executing** (BE_GRANT_10) [intent_test.zig:123].
7. **matchForGrant returns THE one pending; beginExecuting transitions it**
   [intent_test.zig:137]; beginExecuting on non-pending refused [intent_test.zig:149].
8. **MD4 churn: expired generations NEVER exhaust the table** [intent_test.zig:162]:
   loop >= 2*MAX admissions across generations; table still admits after. Rust: same test
   with 512+ admissions cycling u128 LE intent ids.
9. **Lookups never match a rejected entry** [intent_test.zig:193] - state filter tested
   directly (this killed mutation mutant d089/intent-terminality; keep it as named test).

## MD4 note for implementer

On expiry/refusal of any entry, compact live entries forward (preserve order);
caller-held indices are consumed same-frame only (BE-GRANT-03a). In Rust prefer
index-free handles OR document the frame discipline loudly in code.
