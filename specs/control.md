# stage2 sheet 15/42 - control (HTTP front door)

W5 | source: `../bolina/src/control.zig` (444 lines) | tests: `../bolina/src/control_test.zig` (8 named) | Rust target: `src/bin/bolina` (poll loop owns this module)

## Contract

Single-threaded TCP front door multiplexed into the SAME poll() loop as the UDP wire.
One loop, zero threads: wire fd + listener fd + client slots are all poll entries in
one pass. The control plane can never starve or reorder the wire protocol, and vice versa.

## Public surface

- bind(opt-in spec from env `BOLINA_CONTROL`, default `127.0.0.1:7421`) -> listener fd; EADDRINUSE is boot-fatal (fail-closed)
- poll integration: accept new conns into slots, advance per-conn state machine on readable events
- request lifecycle states: reading headers -> (optional body) -> writing response -> close
- `Connection: close` ALWAYS: one request per connection, `Content-Length` on every reply, chunked responses never emitted

## Hard numbers (byte-exact, cited)

| Thing | Value | Anchor |
|---|---|---|
| Connection deadline | `CONN_TIMEOUT_MS = 5000` | control.zig:73 |
| Slowloris size guard | >=1024 bytes with NO newline = reject immediately (dies by SIZE before deadline) | control.zig:264 |
| Default bind | `127.0.0.1:7421`, opt-in via env only | control.zig:4 |
| Max concurrent clients | table-full reply is 503, existing conns never evicted | control_test.zig:303 |

## HTTP parsing rules (each has a named test upstream)

1. Single-SP request line; obs-fold rejected; space-before-colon rejected; bare control chars in target rejected
2. `Transfer-Encoding` present => **501 explicit** (never a silent drop)
3. Duplicate Content-Length accepted ONLY when byte-equal, else reject; POST without Content-Length => 400 (LengthRequired mapping)
4. Header block that exceeds the cap without terminator => 400 die fast (control_test.zig:251)

## Auth model

- Bearer token required on ALL paths except `GET /healthz` (open by design decision F7/D-091)
- Token file written 0600 at boot, generated once from CSPRNG, printed to console exactly once, never rotated silently
- Compare is constant-time WITH a length pre-check (length leaks, contents do not)
- Missing/wrong token => 403 BEFORE any routing info leaks; valid token + unknown path => 404 (control_test.zig:268)

## Rust test checklist (names preserved from control_test.zig)

- [ ] healthz answers 200 open, no token required (:194)
- [ ] incremental delivery: three dribbles then completion (:207)
- [ ] slowloris idle past deadline swept closed WITHOUT a reply (:227)
- [ ] chunked transfer encoding refused with 501 explicitly (:242)
- [ ] header block unterminated inside cap dies 400 (:251)
- [ ] auth gate: 403 missing / 403 wrong / valid reaches routing 404 (:268)
- [ ] POST without Content-Length is 400 (:294)
- [ ] full table overflows: newest conn reads 503, none evicted (:303)

## Inherited house lessons (non-negotiable in Rust port)

- Client sockets non-blocking with REAL per-OS constant (O_NONBLOCK differs macOS/Linux; a wrong constant makes recv block forever). Zero-blind-faith comments: assert the fcntl result.
- Every read bounded: SO_RCVTIMEO + wall-clock budget. A silent/mutated server must produce fast failure, NEVER an infinite recv (9h-wedge institutional memory).
- Conformance proof for W5: pilot e2e twin runs against this door; curl smoke suite mirrors the Zig live checks (healthz/auth/chunked/SIGTERM drain).
