# binding.zig — cert validation + session binding contract

Source: `src/binding.zig` (190 lines) · Tests: `src/binding_test.zig` (BE_<CLASS>_<NN> naming, build.zig M1 registry) · refs f:line.

## Public surface
- Re-exported lens from parser/session: LEN_PUBKEY=32, LEN_SIG=64, LEN_OVERLAY_ADDR=16, DOMAIN_CERT=0x01 (binding.zig:24-27)
- `DOMAIN_BINDING = 0x05` — BE-SIG-01 tag for handshake binding over Noise h (binding.zig:28). Hard constant; never computed.
- Roles: ROLE_AGENT=1<<1, ROLE_EXECUTOR=1<<2, ROLE_APPROVER=1<<3 (binding.zig:33-35)
- `MAX_PRIVILEGED_LIFETIME_MS = 2_592_000_000` — BE-REV-01 30-day cap (binding.zig:36)
- `APPROVER_QUORUM = 2` — BE-ID-04 approver needs >=2 CA sigs (binding.zig:38)
- `deriveOverlayAddr(sig_pubkey) [16]u8` (binding.zig:84): fd prefix + blake2s(sig_pubkey)[0..15] masked; test BE_ID_01 binding_test.zig:28.
- `checkRoleConstraints(role_bits)` (binding.zig:98) — forbidden pairings refused; test BE_ID_03 :46.
- `validateCert(cert, trusted_cas, now_ms) BindingError!` — clocked path (binding.zig:113)
- `validateCertNoClock(cert, trusted) CertChainError!` — audit path; the ERROR SET CANNOT NAME CertExpired so the type system proves no clock check hides there (binding.zig:127-138). v0.6-era split, keep it verbatim in Rust design.
- `bindSession(cert, binding_sig, handshake_hash, remote_kex_pubkey, trusted, now_ms)` (binding.zig:181)

## Invariants
1. **F1 kex-binding**: bindSession takes remote_kex_pubkey and refuses KexPubkeyMismatch when cert.kex_pubkey != handshake's authenticated static key. Signature shape IS the fix; do not drop the parameter in Rust.
2. Binding sig covers exactly `0x05 || handshake_hash`, chunked identical to the streaming verifier (tag-then-tbs), both directions (BE-TR-01).
3. Scope enforcement gate lives on version: `cert.version >= 3` else scope checks 3a/4a skipped. **v3-with-empty-scopes = deny-all by D-085 R4** (the F15 lesson); v2 certs only exist as history.
4. validateCert enforces roles+quorum+span cap(<=30d)+CA sig count vs role (approver>=2) + trust set membership.
5. Error sets are closed lists (D-049): Rust enums must mirror them 1:1 including CertChainError not containing expiry.

## Test checklist (ported by name)
- BE_ID_01 overlay addr derivation (fd prefix bytes exact) :28
- BE_ID_03 role pairing refusals :46
- quorum: approver with 1 CA sig refused
- span cap: privileged cert >30d refused (BE_REV_01)
- F1 e2e: wrong-kex bind refused (pilot heritage)

## Heritage notes for Rust port
- Do NOT merge validateCert/NoClock into one function with a flag — the separate error set is the proof mechanism (postmortem lesson §7).
