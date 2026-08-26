# sheet: relay_store.zig (store-and-forward mesh buffer) — W5

Source: bolina/src/relay_store.zig (143 lines). Tests: src/relay_store_test.zig (7).

## Contract
BE-MESH-02/03 bounded store-and-forward: recipients addressed by 16-byte overlay addr; packets stored opaque (never parsed), drained byte-for-byte, TTL-lazy-expired on the CALLER's clock. Hard caps everywhere: MAX_BODY=2048, MAX_PER_RECIPIENT=64, MAX_BYTES_PER_RECIPIENT=4MiB, TTL_MS=120_000 (one rekey interval, BE-TR-02), MAX_STORED=1024 global slots.

## Public API
- consts :27-31 ; `StoreError = { BodyTooLarge, PerRecipientFull, StoreFull, ... }` :33
- `StoredPacket` :39 / `DrainedPacket` :48 (drain returns storage order + remaining count)
- Store: `reset()` :60 · `store(recipient_addr[16], sender_index u32, body, now_ms) StoreError!void` :71 · `drainNext(recipient_addr, now_ms) ?DrainedPacket` :110 · `purgeExpired(now_ms) usize` :131

## Invariants (kill-proof obligations)
1. Opacity: drain returns EXACT stored bytes — no parse, no reframe — test :19 pins byte-for-byte equality (BE-MESH-02 opacity holds through BE_MESH_03 mechanics).
2. Caps precedence: oversized body refuses WITHOUT consuming quota (queue untouched); per-recipient full counts as refusal event; global 1024 across all recipients — tests :30/:42/:55.
3. TTL lazy: expiry happens during drainNext/purge against caller-provided now_ms — NO internal timer, no background task (single-threaded discipline) — test :70.
4. Drain order = storage order per recipient; recipients isolated (A's quota full does not block B) — test :82.
5. sender_index rides UNINTERPRETED (opaque u32 from wire header); validity belongs to session layer.
6. purgeExpired returns COUNT purged (observable for metrics/mutation tests).

## Rust port notes
Fixed-cap array-of-slots like source (zero alloc), recipient keying by [u8;16]. Keep refusal-vs-success return distinctions exhaustive. Every cap gets its own named assert in tests; mutation targets later should include each cap constant and the TTL comparison operator.
