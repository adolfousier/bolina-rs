# Stage-2 contract sheet: session.zig

Source of truth: `~/srv/zig/bolina/src/session.zig` (216 lines) + `src/session_test.zig` (13 tests).
Rust target module: `crates/bolina/src/transport.rs` (W4/W5 boundary).

## Purpose

Transport sessions after handshake completion: CipherState/RecvState pairings keyed by
local slot index, sliding replay window, rekey triggers. Wire types 4. SPEC BE-TR-02/03/05/06.

## Constants (cite these exactly)

| Const | Value | Line |
|---|---|---|
| MAX_SESSIONS | 512 | session.zig:37 |
| REKEY_AFTER_MS | 120_000 | session.zig:42 |
| REKEY_AFTER_MESSAGES | 1 << 48 | session.zig:43 |
| HEADER_SIZE | 16 | session.zig:46 |
| MSG_TYPE_TRANSPORT | 4 | session.zig:47 |

## Error set

`Error` at session.zig:49. Rust: single `TransportError` enum; keep variants exhaustive
and closed (no catch-all), matching D-049 discipline.

## Public API (signatures to preserve semantically)

- `CipherState.seal(cs, out, plaintext, ad)` :67 / `.zero()` :76
- `RecvState.open(rs, out, ad, ct, counter)` :90 / `.zero()` :98
- `Session.dueForRekey(s, now_ms) bool` :119
- `Session.seal(s, out, plaintext) usize` :128
- `Session.open(s, packet, hdr: DataPacketHeader, out) usize` :142
- `Session.rotate(s, result: HandshakeResult, now_ms) void` :153
- `SessionTable.init/lookup(local_index)/admit(peer_index,result,now_ms)/release(local_index)` :170/:175/:186/:209

## Invariants (each = Rust test)

1. **Rekey rotation zeroes old state, restarts epoch** (BE_TR_02): `rotate` MUST zero both
   CipherState+RecvState of the replaced generation before installing new keys
   [session_test.zig:33]. Zeroization wipes key material [session_test.zig:58].
   -> Rust: overwrite with zeros, not `drop`; add a "bytes are zeroed" test like Zig does.
2. **Hard message bound**: `seal` refuses at 2^48 messages [session_test.zig:71].
3. **Rekey due at exactly 120s** - strict comparison, NOT a millisecond before
   [session_test.zig:86]. Rust: `now_ms > last + REKEY_AFTER_MS` semantics verified by test.
4. **Frame layout = SPEC 4.1a; keepalive is exactly 32 bytes** [session_test.zig:97].
   Byte-level test required in Rust (16B header + type 4).
5. **Sliding window (BE_TR_03)**: reordered packets within window OPEN [session_test.zig:113];
   a true replay refused [same]; below-window-floor counter refused [session_test.zig:141];
   tampered payload fails AEAD tag [session_test.zig:167].
6. **Ceiling refuses new without degrading existing** (BE_TR_05, MAX_SESSIONS)
   [session_test.zig:183]; ceiling agrees with the reassembly module's declaration
   [session_test.zig:225] -> Rust: static assertion cross-linking both constants.
7. **Release zeroes the whole slot** [session_test.zig:204]; lookup rejects stale or
   out-of-range receiver index [session_test.zig:216] (bounds check BEFORE slice access).
8. **Transport failure surfaces as error only** (BE_TR_06) [session_test.zig:239]:
   no panic path, no partial mutation on error. Rust: all fallible ops return Result,
   mutate state only after validation succeeds.
