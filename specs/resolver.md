# resolver.zig — resource identity + canonical set contract

Source: `src/resolver.zig` (322 lines) · Tests: `src/resolver_test.zig` · refs f:line.

## Public surface
- FP_BYTES=8, FP_HEX_LEN=16, NS_MAX=32, PATH_MAX=180 (resolver.zig:37-40)
- `ID_MAX = 4+16+1+32+1+180` (resolver.zig:42) — derive as expr, keep exact sum.
- DOMAIN_RESOURCE_SET=0x08 BE-SIG-01 tag for the signed published set (resolver.zig:43)
- MAX_RESOURCES=32, MAX_ALIASES=64 — declared capacities; **overflow refuses, never grows** (resolver.zig:45-46)
- ResolveError closed set (:52)
- `executorFp(sig_pubkey,out*[16])` (:87) lowercase hex of BLAKE2s[0..8] — same derivation as keys.fingerprint (single source in Rust).
- `validateCanonical(id)->bool` strict grammar (:104): `bol:<fp16-hex>/<ns>/<path>` with ns [a-z0-9-]{1..32}, path [a-z0-9-._/]{1..180}.
- `Resolver{ add/resolve/resolveAndAdmit/publish }` struct :160.

## Invariants
1. Grammar enforced BEFORE anything else; malformed never enters state (BE_RES_01 tests :53, :188 admission stores CANONICAL form never the proposal).
2. Unknown resource refuses; ambiguous spelling refuses; **nothing created on either** (BE_RES_02 :85, :214 "table untouched").
3. Aliases map to exactly one canonical; two spellings collapse into one lock domain (BE_RES_03 :105, :201).
4. **BE_RES_04 foreign fingerprint**: a canonical carrying an fp != own executor fp is refused at ADMISSION (not at grammar). Test :126 standalone, :222 table-untouched variant. This was the P2 smoke discovery — operator must declare resources whose fp == daemon's own fp.
5. Published resource set is SIGNED STATE over DOMAIN_RESOURCE_SET (0x08); tamper refuses (BE_RES_05 :135).
6. Granularity declared: capacities refuse at overflow (BE_RES_05 granularity test :165) — mirrors MD4 anti-churn philosophy.
7. resolveAndAdmit enforces per-resource exclusivity: second pending on same canonical => ResourceHeld (verify_test/dispatch heritage; discovery from P2 live smoke).

## Rust translation notes
- Keep ResolveError exhaustive; map Zig error union to Result<T,E> without panics.
- Canonicalization BEFORE compare everywhere (store canonical only); alias resolution must not bypass grammar.
