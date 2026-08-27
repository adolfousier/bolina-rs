# keys.zig — node key material contract

Source: `src/keys.zig` (194 lines) · Tests: `src/keys_test.zig` · Zig refs cited f:line.

## Public surface
- `MAX_CAS=8`, `MAX_CERT=1024`, `KEY_LEN=32`, `MAX_PATH=256` (keys.zig:25-28)
- `KeysError{ DataDirUnwritable, KeyFileCorrupt, PubMismatch, CertTooLarge, DiskError }` (keys.zig:30) — D-049 distinct errors; map to a closed Rust enum.
- `readKeyFile(io,path,out[32]) -> bool` (found / absent=false) (keys.zig:57)
- `writeKeyFile` (keys.zig:69)
- `fingerprint(pubkey) [16]u8` = hex16 of BLAKE2s-256(pubkey)[0..8] (keys.zig:157) — SAME value resolver FP uses (BE-RES-06); single implementation, never two.
- `loadOrGenerate(data_dir) Keys` (keys.zig:173)

## Invariants (each must have a named Rust test)
1. First run generates real X25519+Ed25519 material; second run reloads byte-identical keys (D-018 anti-zeroed-keys). Test: keys_test.zig:69.
2. Secret files 0600, dir 0700 (checked by perms assertions in gen path).
3. Stored pub cross-checked against derived-from-secret via timing_safe compare; tamper => `PubMismatch`, distinct from missing-file. Test: keys_test.zig:96 "tampered static.pub is a distinct fatal, never silently accepted".
4. Truncated secret file = corruption, NOT silent regeneration. Test: keys_test.zig:114.
5. cert.bin loads verbatim (up to 1024); ABSENT stays unbound-accept mode (len=0), never an error. Test: keys_test.zig:132.
6. CA pubs load from `ca/ca0.pub..ca7.pub` in LABEL ORDER; order matters downstream (cert sig slots). Test: keys_test.zig:152.
7. fingerprint is stable lowercase hex over the pubkey PREFIX (32B input). Test: keys_test.zig:182.

## Rust translation notes
- Permissions semantics differ per platform in std::fs::Permissions; use unix PermissionsExt on the seam module only. Behavior gate: same accept/refuse matrix as tests above.
- Constant-time eq of PUBLIC keys is belt-and-braces (public data) but keep it: `subtle` not allowed (dep policy A allows audited crates; if unused extra dep hurts, hand-roll double-[u8] branchless fold — cite original in comment).

## Wire/binary formats pinned here
None on the wire. On-disk ONLY. File layout referenced by daemon boot order (D-089).
