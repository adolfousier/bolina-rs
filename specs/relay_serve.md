# Sheet: relay_serve (stage-2 contract)

Source: `~/srv/zig/bolina/src/relay_serve.zig` (216 lines) · tests: `src/relay_serve_test.zig` (6 named)
Wave target: W4/W5 · BE anchors: BE-EXEC-04

## Contract

Relay role service: classifier + forwarder + store-and-forward post office for relay
traffic, sitting beside the handshake server on the SAME socket fd.

## Public surface (verbatim from source)

- `MAX_SA_LEN: c_uint = 28` (sockaddr buffer; line 26)
- `MAX_ENDPOINTS: usize = 128`; `MAX_DRAIN_BATCH = relay_store.MAX_PER_RECIPIENT` (lines 27/33)
- `Endpoint { .. }`, `EndpointMap { put/get/remove }` — index->sockaddr map (line 33+)
- `ServeResult enum { to_handshake, forwarded, stored, registered, drained, dropped }` (line 86) — 6 outcomes, exhaustive in Rust
- `RecvError = error{RecvFailed}` only
- `RelayServe { fd, sessions: *HandshakeServer, table: *RelayTable, store: *Store,
  endpoints, counters..., sig_pubkey_for_slot: fn(usize) ?[32]u8 }` (line 97)
- `serveOne(buf, now_ms)` — recvfrom + dispatch, caller owns buffer and clock (line 114)
- `serveDatagram(dgram, src_sa, sa_len, now_ms)` — pure classifier entry (line 124)

## Classifier (BE-EXEC_04), serveDatagram line 124+

First byte routes:
| byte | action |
|---|---|
| 1,2,3 | handshake machinery (`to_handshake`) |
| relay.MSG_RELAY_ROUTE | live forward OR deferred store |
| relay.MSG_RELAY_REGISTRATION | registration (+ stored-queue drain) |
| anything else / empty dgram | `.drop()` — no service |

Rust note: use match with exhaustive catch-all arm calling `drop()`; never panic on
unknown types.

## Identity seam (D-059 shape) — INTANGIBLE, keep verbatim

The daemon supplies client sig_pubkey for a committed session slot via callback;
handshake table holds X25519 statics only. **Returning null REFUSES the registration.**
In Rust: `Box<dyn Fn(usize) -> Option<[u8;32]> + Send>` or generic param — decision at W5;
null-refusal is a named test below.

## Named tests to port 1:1 (relay_serve_test.zig)

1. `:140` "BE_EXEC_04 classifier routes handshake types and drops everything else"
2. `:184` "BE_EXEC_04 T1 forward live: registered recipient gets the body byte-for-byte"
3. `:237` "BE_EXEC_04 sender gate: no established session, no service"
4. `:285` "BE_EXEC_04 T2 store then drain: late registration drains in order with rewritten index"
5. `:357` "BE_EXEC_04 T3 bounds: quota drop at 65, expiry pruned at registration"
6. `:411` "BE_EXEC_04 registration gates: signature, overlay, relay_index, skew, table bound"

Invariant chain: sender gate (established session) precedes ALL service; quota drop at
65 per recipient; expiry pruned AT REGISTRATION TIME not lazily; late registrants get
in-order drain with rewritten recipient index.
