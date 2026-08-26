# TODO (Huntley stage-3 driver)

Rule: ONE item "now" at a time. When done, mark [x], promote the next, `git commit`, loop.
Citations pull `file_read` back to `~/srv/rs/bolina` (original Zig tree) while implementing here.

## NOW

Build stage-2 contract sheets 10..42 into specs/ (order: next-smallest-first). DONE so far: render, handshake, token, historical, replay, http_parse, mac, listener, relay_store (9/42).
Sheet standard set by specs/render.md: public signatures, error set, invariants w/ BE-* links,
test-semantics checklist as future asserts, file:line citations only (never "the spec in general").
No sheet, no wave. After each batch: push, tick LOGBOOK.

## Waves

- [x] W0 workspace + strict lints + ReleaseSafe-parity profile (969a812)
- [ ] W1 crypto head, crates per D-096-A (dalek family + RustCrypto, pinned), KATs RFC 7748/8032/8439/7693 green
- [ ] W2 codec vs test/vectors.json frozen byte-for-byte, negatives included
- [ ] W3 intent table + grant ledger durable I/O (flock via seam)
- [ ] W4 Noise_IK + handshake + binding - INTEROP LIVE vs Zig daemon (G2 ladder A/B/C)
- [ ] W5 listener/relay/session/daemon + control plane HTTP (pilot e2e analog)
- [ ] W6 ca CLI + keys (cross-acceptance Zig verifier <-> Rust material)

## Unbreakable rules

1. NO swap of reference head until W6 parity + new full battery (mutation domains, cross-diff
   Zig-vs-Rust, re-soak on owner's box) + owner's explicit declaration (D-096).
2. Bugfixes land in Zig FIRST while it stays reference; sheet updated same commit; wave absorbs.
3. Bytes are built field-by-field; no transmute/as_bytes of protocol structs (E2).
4. No async runtime (tokio et al) until post-swap review (E4); mirror the single-threaded poll design.
5. Every gate crossed gets a lastro receipt where feasible and one LOGBOOK line (signal, no noise).
