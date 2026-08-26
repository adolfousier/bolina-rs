# sheet: replay.zig (anti-replay window) — W4 transport

Source: bolina/src/replay.zig (114 lines). Tests: src/replay_test.zig (8).

## Contract
BE-TR-03 1024-bit sliding replay window over u64 counters, per session per direction. Fresh counter inside or ahead of window -> true + recorded; already-seen or below-window -> false. First call seeds with WHATEVER arrives, including 0 (0 is legal first counter, NOT a sentinel).

## Public API
- consts: `WINDOW_BITS=1024`, `WORD_BITS=64`, `WINDOW_WORDS=16` — replay.zig:38-42
- `ReplayWindow{ window:[16]u64, largest:u64, initialized:bool }` — :44-48
- `check(self, counter: u64) bool` — :58

## Invariants (kill-proof obligations)
1. Init seeds largest on FIRST packet whatever its value; bit 0 marks it — :59-64. Counter 0 treated as ordinary value (test at replay_test.zig:73 pins the anti-sentinel property).
2. Advance ages every bit by the gap, drops past far edge, marks new top — :66-74.
3. `diff >= WINDOW_BITS` -> stale reject BEFORE indexing (no OOB) — :78.
4. shiftLeft processes high->low word so each destination writes before its source reads (in-place safety) — comment :88-91, impl :100-113. Shift >= window width zeroes entirely — :93-95.
5. Zig note for port: u6 @intCast tricks exist because shifts need typed bits; in Rust use checked shl with u32 or `(1u64 << b)` after b<64 guard — semantics identical.

## Test checklist (port as named tests)
- first seeds + replay of it rejected :13; exact duplicate rejected :19; reorder-inside-window accepted :28; below-window rejected :41; advance keeps recent visible to later reorder :48; jump beyond width clears bitmap entirely :62; counter-0-not-sentinel :73; scrambled distinct within one window all accepted then all replayed :80.
