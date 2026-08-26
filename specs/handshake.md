# Contract sheet: handshake.zig

Source of truth: `~/srv/zig/bolina/src/handshake.zig` (75 lines).
Tests ported from: `handshake_test.zig` (147 lines).

## What it is

Live Noise_IK handshake responder over the listener socket (SPEC 4.1,
BE-SESS-02). Type-1 initiations only at this layer; mac2 cookie is declared
phase C and answered with a zero cookie (`handshake.zig:11-14`).

## Public surface (Rust must mirror semantics, not names)

- `MAX_SESSIONS: usize = 16` (`handshake.zig:25`)
- `Session { send_key[32], recv_key[32], handshake_hash[32], peer_static[32] }`
  (`handshake.zig:27-33`) - `peer_static` is the INITIATOR static recovered
  from IK, not a config value.
- `HandshakeError = { NotInitiation, TableFull, Refused, SendFailed }`
  (`handshake.zig:34`) - D-049: distinct outcomes stay distinct.
- `processDatagram(datagram, reply_sa, reply_sa_len) -> slot index`
  (`handshake.zig:48`). NOTE: the Zig signature takes `now_ms` but ignores it
  (`_ = now_ms`, `handshake.zig:49`); timestamp replay policy is session-layer
  work (SPEC 2.2). The Rust head may drop the param, but must document that.

## Invariants (each with its BE link)

1. **BE-SESS-02 single-commit**: the session table is mutated in exactly one
   place - the commit block after `responder.finalize()`
   (`handshake.zig:64-72`). Every failure path returns BEFORE it; a failed
   handshake leaves zero half-session state.
2. **Ordering inside processDatagram** (`handshake.zig:50-63`): type/length
   check -> table capacity check -> full Noise verify (mac1 + decrypt,
   `readInitiation`) -> build response -> sendto (exact-length send or
   `SendFailed`) -> finalize -> commit. Failures before send return `Refused`
   / `NotInitiation` / `TableFull`.
3. **Type-2 index layout is SPEC-conformant** (`handshake.zig:58-61`,
   comment block 55-57): our newly chosen slot goes as the responder's
   sender_index; the initiator's sender_index echoes back. The G2 live interop
   found these swapped once (bug e4fd0d4); the Rust port inherits the FIXED
   layout and a byte-level pin test.
4. **Reply transport**: flat `sendto(2)` on the bound listener fd, exact
   length required (`handshake.zig:22, 62-63`).

## Test checklist -> Rust asserts

| Zig test | line | Rust assert |
|---|---|---|
| success over listener commits exactly one session | `handshake_test.zig:58` | happy msg1 -> 1 session, keys match Initiator side |
| refused mac1 leaves zero half-session | `handshake_test.zig:109` | tampered mac1 -> Err(Refused), `session_count == 0` |
| truncated and wrong-type datagrams leave zero half-session | `handshake_test.zig:130` | short datagram + wrong type byte -> `NotInitiation`, count 0 |

## Rust-side notes

- Lives in the W4 wave; depends on the crypto head (W1) and noise IK module.
- `sendto` seam lives behind the same single audited extern module as poll/
  flock (plan §4 note). In tests, replace with an injected sink so asserts do
  not need real sockets except the live-interop ones.
