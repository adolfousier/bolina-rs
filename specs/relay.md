# relay.zig — mesh registration + route frames contract (256-line cap file)

Source: `src/relay.zig` (**EXACTLY 256 lines** — D-052 density rule; Rust port free of cap but keep density) · refs f:line.

## Frame constants (all wire-pinned)
- MSG_RELAY_ROUTE=0x05, MSG_RELAY_REGISTRATION=0x06, DOMAIN_RELAY_REGISTRATION=0x07 BE-SIG-01 (relay.zig:19-21)
- LEN_RELAY_ROUTE=20, LEN_RELAY_REGISTRATION=124 with layouts in comment :23-24
- LEN_RESERVED=3, overlay_addr=16, sig=64, padding=16 (:25-28)
- MAX_RELAY_TABLE=4096 bounded table (D-044) :30 · TIMESTAMP_SKEW=300s :31 · MAX_EXPIRY=86400s client cap :32

## Parsers (strict, parser.ParseError family)
- parseRelayRoute: wrong type / non-zero reserved / trailing bytes / truncated ALL refuse. Tests relay_test.zig:35-64.
- parseRelayRegistration same refusals + expiry<=MAX_EXPIRY, skew window check. Tests :69-101.

## Table semantics (MD5 heritage)
- insert(): **dedup by overlay_addr FIRST** — existing addr => refresh in place (return true); NEW addr at capacity => false; capacity never exceeded. Test "rejects insert when full" must use a byte pattern no loop entry sets (relay_test.zig:121 heritage fix).
- Registration re-submission refreshes TTL, never duplicates route.
- Expiry prune: skipped/expired corpses removed; the terminality-filter test that killed the d089-era mutant pins lookup state filters — port that named test.

## Invariant for Rust
- Ordering rule from MD5 mutant lineage: refresh-vs-insert precedence changes observable capacity behavior; kill-proof = full-table insert cycle then re-register one entry, capacity stays MAX and original slot content refreshed.
