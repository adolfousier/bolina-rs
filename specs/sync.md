# Sheet: sync (stage-2 contract)

Source: `~/srv/zig/bolina/src/sync.zig` (289 lines) · tests: `src/sync_test.zig` (8 named)
Wave target: W4/W5 · BE anchors: BE-SYNC-01..05

## Public surface (verbatim)

Constants (source lines 33-41):
- `MAX_RESPONSE_ENVELOPES = 64` (responder ceiling)
- `MAX_RESPONSE_BYTES = 1 << 20` (1 MiB per response)
- `RESPONSE_HEADER = 34` (version u8 | channel_id [32] | count u8)
- `WALK_MAX_DEPTH = 128`, `WALK_MAX_TOTAL = 4096` (sync walk bounds)
- `RATE_WINDOW_MS = 10_000` sliding window (D-054); `SERVE_BUDGET = 8`, `ISSUE_BUDGET = 4`
- `MAX_TRACKED_PEERS = 64` fixed rate table; FULL REFUSES (fail closed, no eviction)
- `SyncError{...}` (7 entries, line 43 — port as exact Rust error enum, same names)
- `admit(...)`, `RateWindow.init/admit`, `RateTable.admit(peer[32], window_ms, now_ms)`,
  `ServeItem`, response builder

## Semantics pinned by tests (sync_test.zig)

1. `:28` sync request round trip (encode=decode identity)
2. `:65` sync response round trip
3. `:124` **BE_SYNC_01** admission requires an ESTABLISHED session + member + not revoked
   (three-gate conjunct; any fail => refuse BEFORE rate table)
4. `:146` **BE_SYNC_02** cap = min(max_envelopes, 64), hard stop at 1 MiB mid-envelope
   truncation EXACT (never partial envelope bytes), response STATELESS (no queue memory)
5. `:225` **BE_SYNC_03** walk stops at depth 128 AND total 4096; UNRESOLVED parents are
   SURFACED (reported back), NEVER retried inside the walk
6. `:249` **BE_SYNC_04** 9th served request in window refused; window slides by time;
   serve budget 8 symmetric with issue budget 4; full peer table fails closed
7. `:301` **BE_SYNC_05** backfilled envelope passes the LIVE signature check before adopt
   (no trust shortcut for gap-fills)

Response layout invariant: header exactly 34 bytes; count fits u8; total-bytes budget
checked BEFORE appending each envelope (`pos + need + 1 > MAX_RESPONSE_BYTES => break`,
source line 187) so an envelope is either fully present or fully absent.
