# parser.zig -> codec::wire (W2 support)

Source: `src/parser.zig` (328 lines). Sub-modules `parser/channel.zig`, `parser/session.zig`, `parser/sync.zig` imported at L41-43 share the SAME Cursor reader so the truncation exit point stays ONE site (comment L96-102).

## Contract

Bounds-checked, ZERO-HEAP parsing of every wire message type. Every read routes through `Cursor.need()` (BE-WIRE-02 as construction, not hope - comment L101).

## Normative constants (Rust: `pub const` identical values)

| Const | Value | Source |
|---|---|---|
| MAX_MESSAGE | 1 << 20 (1 MiB reassembly ceiling) | parser.zig:54 |
| LEN_PUBKEY / LEN_EPHEMERAL | 32 / 32 | :55,58 |
| LEN_RESERVED | 3 (type byte + reserved, SPEC 2.2/4.1a) | :57 |
| LEN_AEAD_TAG / LEN_NONCE | 16 / 12 | :59,60 |
| LEN_MAC | 16 (mac1/mac2 keyed-BLAKE2s-128, SPEC 4.4) | :61 |
| LEN_ENCRYPTED_STATIC / _TIMESTAMP / _NOTHING / _COOKIE | 48 / 24 / 16 / 32 | :62-65 |
| LEN_TRANSPORT_HEADER | 16 (SPEC 4.1a) | :66 |
| MAX_PACKET | 1400 (BE-TR-05) | :67 |
| MSG_HANDSHAKE_INITIATION..MSG_TRANSPORT_DATA | 1,2,3,4 | :72-75 |
| DOMAIN_HANDSHAKE | 0x05 | :81 |

## Error set (exact, no extras)

ParseError (parser.zig:88-94): `Truncated` / `Oversize` / `TrailingBytes` / `Malformed`. Malformed is EXACTLY wrong-type-byte OR non-zero reserved byte (SPEC 4.1a, 2.2). Rust: one enum, four variants, `#[non_exhaustive]` forbidden - exhaustiveness is the point.

## Public API

- `Cursor`: u8r/u16be/u32be/u64be/take(n)/field16(max)/field32(max32) - parser.zig:104-160. fieldN reads length prefix then bounds-checks payload.
- `parseHandshakeInitiation(buf)` -> struct @201; `parseHandshakeResponse` @238; `parseCookieReply` @272; `parseDataPacketHeader` @303-309.

## Required Rust tests (named identically)

From `parser_test.zig` (M1 registry naming):
- "BE_WIRE_01 envelope round-trips the canonical vector, zero heap" (:47)
- "BE_BODY_01 intent body slices the opaque action without parsing it" (:68)
- BE_WIRE_02 family (:79,85,92,103,110,114): truncated signature, trailing byte, oversize body_len before any large read, parent_count above bound, empty input, intent trailing byte.
- Handshake initiation/response/cookie round-trips pinned layout (:152,206,251) with rejection twins: wrong type byte => Malformed (:170,218), NON-ZERO RESERVED => Malformed (:176,224), trailing bytes (:182,230), truncated (:190,238).

## Heritage notes

- Non-zero-reserved rejection is the byte discipline family of the type-2 index swap caught live in G2 - if Rust ever relaxes it, conformant peers break silently.
- WIRE_01 tests assert zero allocations: port must keep alloc-free parsing (`&[u8]` slices only).
