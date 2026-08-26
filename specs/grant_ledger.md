# Stage-2 contract sheet: `grant_ledger.zig` (554 lines)

Zig source: `src/grant_ledger.zig` @ bolina main (`d24cf74`). Tests: `src/grant_ledger_test.zig` (404 lines).
Wave target: **W3**. BE anchors: BE-GRANT-01/01a, BE-REV-02, BE-HIST-04, D-061/D-062/D-064 R1.

## Contract

Durable two-phase append log for consumed grants (commit -> publish tombstone),
revocations keyed by signer pubkey, and first-receipt times keyed by grant_id.
Single-writer (exclusive flock at open, MD3). The live in-memory cache mirrors the
log tail; the on-disk log is THE state (recovery rebuilds cache from records).
Everything is bounded: MAX_LIVE=1024 live entries, buffer allocated to actual
file length on recover/prune (F2 fix).

## Public surface (all under `GrantLedger`, Zig lines 142-517)

| Fn | Signature | Notes |
|---|---|---|
| `open` | `(io, path) !GrantLedger` | creates if absent; **flock LOCK_EX\|LOCK_NB** -> `error.Locked` if held (line 142) |
| `openReadOnly` | `(io, path) !GrantLedger` | NO lock; mutating ops fail DiskError through read-only handle (line 164, MD3 audit views) |
| `recover` | `(*self) !Recovery` | replays log; returns `{orphans, consumed_count, revoked_count}`; orphans BORROW internal buf, valid until next mutator (line 181) |
| `commitConsumed` | `(*self, grant_id[16], expiry_ms, now_ms) !void` | idempotent: re-committing spent id = no-op (line 265) |
| `markPublished` | `(*self, grant_id[16]) !void` | tombstone row (line 283) |
| `isConsumed` / `isPublished` | `(*self, grant_id[16]) bool` | lookups IGNORE expired/rejected rows (pinned by intent terminality test) |
| `commitRevocation` | `(*self, sig_pubkey[32], cert_expiry_ms) !void` | subject-expiry carried for pruning (F6/D-090) (line 315) |
| `isRevoked` | `(*self, sig_pubkey[32]) bool` | |
| `recordFirstReceipt` / `getFirstReceipt` | grant_id-keyed, u64 ms | F4: T_recv anchor survives restart (lines 336/354) |
| `pruneExpired` | `(*self, now_ms) !void` | drops expired consumed grants; **atomic rewrite**: temp + rename + parent-dir fsync; re-flock after reopen (line 374, F3 fix) |
| `close` | `(*self) void` | |

## Error set (line 86, ORDER MATTERS for Rust enum mapping)

`BadLog` (committed record failed parse outside trailing partial) ·
`ResourceExhausted` (live cap reached, prune did not free enough) ·
`DiskError` · `Locked` (MD3 second exclusive open).

## Wire record formats (constants lines 61-73)

| Tag | Byte | Layout |
|---|---|---|
| COMMIT | 0x01 | tag(1) + grant_id(16) + expiry_ms(u64be) = 25 |
| PUBLISHED | 0x02 | tag(1) + grant_id(16) = 17 |
| REVOKE | 0x03 | tag(1) + sig_pubkey(32) + cert_expiry(u64be) = 41 |
| FIRST_RECEIPT | 0x04 | tag(1) + grant_id(16) + time_ms(u64be) = 25 |

Rust rule: little room for invention here — record parsing must reject any
non-canonical length exactly like `BadLog` semantics.

## Invariants (each with its Zig proof, port ALL)

1. **fsync BEFORE effect observable on read-back** (BE-GRANT_01 T1,
   test line 59): commitConsumed returns only after data hits disk.
2. **Restart replays exact state** (T2, test line 86): consumed set
   reconstructs identically.
3. **Crash mid-execution -> orphan publishes ONE interrupted Effect, not retried**
   (BE-GRANT_01a T3, test lines 113/142): un-tombstoned orphan RE-emits on
   next recover (at-least-once, fail-safe direction).
4. **Revocations persist across restart, NEVER pruned** (BE_REV_02 T5,
   test line 170).
5. **pruneExpired drops only expired consumed grants, keeps live ones** (T6,
   test line 197).
6. **Partial trailing record discarded cleanly** (test line 237): torn write =
   ignore tail, never BadLog.
7. **Idempotent commit** (test line 267).
8. **Crash during prune: atomic rewrite intact + stale temp cleaned** (test
   line 298).
9. **Exclusive flock; second open fails Locked; close releases** (MD3,
   test line 356). NOTE: macOS/Linux flock semantics identical here.
10. **First-receipt survives restart: recover replays the anchor row**
    (F4, test line 378).

## Known wart inherited (register, do not fix silently)

Durable-ledger I/O assumptions are part of the Linux test-harness gap
(408/28/7 disclosure): positional reads/writes assume seekable fd behavior
verified on macOS. Rust port uses std::fs equivalents; e2e Linux run required
before parity claim.

## Rust acceptance gate (W3)

All 11 tests above ported as named integration tests against a temp dir;
record-format bytes asserted against these constants; flock seam maps to
libc::flock with LOCK_EX|LOCK_NB identical values (2|4). A reader-only
handle MUST NOT take the lock.
