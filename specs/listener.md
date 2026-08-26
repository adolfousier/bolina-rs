# sheet: listener.zig (UDP endpoints registry + socket seam) — W5 daemon

Source: bolina/src/listener.zig (173 lines). Tests: src/listener_test.zig (7 incl. two OS-socket integration tests marked BE_EXEC_03).

## Contract
Two layers: (a) `EndpointRegistry` — process-local ownership so two components can never bind the same addr:port inside one node (BE_EXEC_02); (b) `Listener` — ONE socket per Family (ipv4|ipv6), binding exactly that family (BE_EXEC_03), with recv/recvFrom flat-libc seams and close.

## Public API
- `Family = enum { ipv4, ipv6 }` — listener.zig:33; `ListenError = { SocketCreateFailed, BindFailed, RecvFailed, ... }` :35
- `MAX_ENDPOINTS = 8` :43 ; `Endpoint{addr,port,family}` :45
- Registry: `owns(addr,port) bool` :58, `claim(addr,port) error{EndpointBusy}!void` :66, `release(addr,port)` :76
- Listener: `open(family)` :98, `bind(registry,addr,port)` :111 (claims registry THEN binds OS; releases on failure), `recv(buf)` :126, `recvFrom(buf,out_addr[28],out_addr_len)` :136 (writes sockaddr in-place into caller buffer — keep the fixed-size form in Rust as [u8;28]+len to avoid net-types churn), `close()` :144

## Invariants (kill-proof obligations)
1. One owner per endpoint: claim twice -> EndpointBusy; release frees; OS-level duplicate bind outside registry still fails its own way — tests :47/:60/:73.
2. A listener is monogamous to one family; wrong-family address -> family mismatch error — :87/:119.
3. bind failure AFTER successful claim must release the registry slot (no leak making endpoint permanently busy) — derived invariant from :111 flow; ADD explicit Rust test if none exists upstream.
4. Sockets: SO_REUSEADDR-style reuse INSIDE registry only where tests demand; O_NONBLOCK and addr-struct constants are PER-OS — this repo has history here (O_NONBLOCK incident): put values behind cfg!(target_os) from day one, NEVER hardcode macOS constants.
5. recv/recvFrom return usize>0 always (datagram either whole or error); no partial datagram concept.

## Test checklist
:47 owns-one-at-a-time · :60 second bind refused · :73 OS duplicate-bind refused · :87 single family · :101 datagrams flow through bound listener (real loopback sockets) · :119 declared family carried by socket. The Linux-harness gap (platform disclosure, f6eb3ac note) lives HERE + relay: prioritize these two sheets' integration tests being made cross-platform-correct in Rust (getpeername paths differ; use libc-bindgen-free std::net::UdpSocket where possible instead of externs — std covers this fully).
