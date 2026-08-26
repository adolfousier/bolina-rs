# sheet: mac.zig (mac1 + cookie, WireGuard-style DoS front) — W4 transport

Source: bolina/src/mac.zig (173 lines). Tests: src/mac_test.zig (9).

## Contract
BE-TR-04 mac1: label-keyed BLAKE2s authenticator ("bolina-mac1-v2", MAC_BYTES=16) over message bytes using the responder's static signature pubkey (32B). Lets a responder filter junk cheaply pre-decryption without state. BE-TR-04a cookie: stateless-ish proof-of-address under rotating secret (COOKIE_ROTATE_MS=120_000) so an unauthenticated flood can be answered without session state.

## Public API
- consts MAC1_LABEL :50, COOKIE_ROTATE_MS :53, MAC_BYTES=16 :56, KEY_BYTES=32 :60, ResponderSigPubkey[32] :65
- `computeMac1(sig_pubkey, msg) -> [16]` — :97 ; `verifyMac1(...) bool-equivalent errors` — :110
- `CookieSecret{ secret, epoch }`: init :139, needsRotate(now) :145, rotate(new_secret, now) :152, issueCookie(source_addr)->[16] :159, verifyCookie(..., now) accepts current-or-previous epoch only :166

## Invariants (kill-proof obligations)
1. Known-answer tests pin BOTH mac1 and cookie against the INDEPENDENT Python vector generator — mac_test.zig:51/:85. The Rust port must consume the SAME frozen vectors file, not freshly generated Zig answers.
2. Single-bit flip in tag must fail verify :61; key change changes tag :67; ANY message byte change changes tag :77 (avalanche).
3. Cookie verify ACCEPTS previous-epoch cookie during rotation overlap, REJECTS older/rotated-out secrets :97 — exactly two live epochs, never silently three.
4. Rotation is explicit (rotate()) and never silent mid-epoch: needsRotate() drives it, host code calls — mirrors token.zig philosophy (rotation failure logged, not swallowed).
5. Constant-time compare for tag bytes (timing-safe eql path from std.crypto.timing_safe in Zig; use subtle/constant_time_eq-equivalent from chosen crates, D-096-A).

## Test checklist
:51 KAT mac1 · :56 fresh accept · :61 bit-flip reject · :67 key-bound · :77 msg-bound · :85 KAT cookie · :91 fresh accept · :97 rotated-secret reject. Port all 9 verbatim; vectors stay frozen JSON in tree.
