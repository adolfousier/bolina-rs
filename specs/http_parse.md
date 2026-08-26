# sheet: http_parse.zig (control-plane HTTP/1.1 subset parser) — W5 control

Source: bolina/src/http_parse.zig (139 lines). Tests: src/http_parse_test.zig (8).

## Contract
Incremental pure parser for the control plane's strict request grammar: single-SP request line, no obs-fold, no space-before-colon, Content-Length framing ONLY (chunked = hard refuse 501 semantics at route level, parser rejects TE outright). It never allocates, never touches sockets; parsing happens against the caller's byte buffer state machine-side (see control sheet later).

## Public API
- `HEADER_CAP = 8192`, `BODY_CAP = 64KiB` — http_parse.zig:27-28
- `ParseError = { Incomplete, HeadersTooLarge, BodyTooLarge, BadRequest(MalformedLine|BadVersion|BadMethod|TransferEncoding|LengthRequired|ConflictingLength|ObsFold|SpaceBeforeColon|DoubleSP|ControlInTarget...) }` union-ish set — :30 (exact shape must mirror error set used by control.zig routing 400/501 mapping F5)
- `Method = enum { get, post }` — :42
- `Request { method, target(+query split), headers slice list, content_length, body_start }` — :50
- `parse(buf []const u8) ParseError!Request` — :61 (pure, zero-copy slices into buf)

## Invariants (kill-proof obligations)
1. Fragmented feed stays `Incomplete` until terminator present; growth past HEADER_CAP dies `HeadersTooLarge` even without terminator (slowloris size-guard, before the 5s deadline) — tests :27/:37.
2. Body cap enforced AT DECLARATION TIME from Content-Length, before any body bytes arrive — test :83.
3. Duplicate Content-Length allowed only when byte-equal; conflicting refused — test :55.
4. Smuggling guards (each its own error): obs-fold, space-before-colon, double-SP request line — test :64; bare controls scanned in target.
5. Pinned rejections: bad version, unknown method, Transfer-Encoding present, missing length on POST — test :44.
6. Body slicing takes EXACTLY clen bytes — test :18 (trailing garbage belongs to next frame handling upstream, not parser).

## Rust notes
Pure functions over &[u8]; keep zero-copy via indices, not &[&str], so token/auth verification compares raw bytes. Error enum MUST be exhaustive like D-049 style: no catch-all.
