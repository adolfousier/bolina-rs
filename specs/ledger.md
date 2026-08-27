# ledger.zig contract sheet (src/ledger.zig, 333 lines)

## Contract
In-memory evidence ledger: hash store of accepted envelopes (BE-LEDGER-02),
per-(sender,channel) replay windows (BE-ENV-03/04), anchor table (BE-HIST-02),
revocation table (BE-HIST-04). Pure slice, no I/O; the DURABLE log is
grant_ledger.zig (separate sheet). Powers admission checks in verify.zig
(allParentsPresent precedes seq/insert: F5 ordering).

## Public surface (cites)
- consts (ledger.zig:26-34): HASH_BYTES=32, LEN_SIG_PUBKEY=32,
  LEN_CHANNEL_ID=32, MAX_ENVELOPES=4096, MAX_SEQ_WINDOWS=256,
  MAX_ANCHORS=256, MAX_REVOCATIONS=64.
- LedgerError (ledger.zig:40-47): StoreFull, SeqWindowsFull, AnchorsFull,
  RevocationsFull, Divergence, WindowStale. Six distinct errors (D-049 rule):
  Rust must mirror one-to-one as an exhaustive enum.
- Ledger.init() :123. Fields are fixed-cap arrays + counts; capacity refusal,
  never growth.
- insertEnvelope(entry) !void :139-161:
  * scan-first for matching (sender, channel, seq): same hash -> idempotent OK;
    different hash -> error.Divergence (BE-ENV-05 equivocation).
  * only after the scan: capacity check StoreFull, then append at count.
  * ORDER MATTERS: dedupe check BEFORE capacity check. A mutant that swaps
    them dies in tests (a re-send of a stored envelope must succeed on a FULL
    store). Kill-proof required by name in Rust tests.
- allParentsPresent(parents) bool :166: true iff EVERY parent hash is present.
  In-memory check only; caller owns fetch budget (BE-LEDGER-01 comment :163).
- checkSeq(sender, channel, seq) !void :187-218: look up window ->
  ReplayWindow.check; miss below window = WindowStale (BE-ENV-04). No window ->
  create (SeqWindowsFull if full) and seed with first call ("first call seeds
  largest", :215).
- setAnchor/getAnchor :220/:244 (BE-HIST-02): FIRST envelope of a pubkey is its
  anchor; idempotent match, Divergence (AnchorsFull paths) on mismatch; anchor
  retrievable past index zero (test ledger_test.zig:169).
- setRevocation(pubkey, revoke_hash, cert_expiry_ms) !void :259-307:
  idempotent on equal hash, Divergence on mismatch (:262-271); F10 pruning:
  when full, evict LOWEST cert_expiry_ms entry first (:273-300); full AND
  nothing prunable -> RevocationsFull.
- isRevoked :310 / getRevokeHash :324 (D-090 causal hook).

## Rust mapping notes
- All four tables: fixed Vec::with_capacity(MAX_*) or boxed arrays + counts.
  No reallocation ever (parity with Zig fixed arrays).
- Errors: `enum LedgerError` exhaustive; no extra variants.
- Idempotent-vs-Divergence shape is a security property: write helper tests
  per table, not one mega-test.

## Tests inherited (name-mandatory in Rust)
From src/ledger_test.zig (marker convention BE_LEDGER_xx):
- :40 envelope stored by HASH not plaintext (BE_LEDGER_02)
- :61/:73 grant + effect envelopes recorded on acceptance (BE_LEDGER_03)
- :97 unknown parents rejected, no budget exceeded (BE_LEDGER_01)
- :112 known parents pass (BE_LEDGER_01)
- :132 first envelope becomes anchor (BE_HIST_02)
- :146 anchor idempotent twice OK; :158 mismatched second call diverges
- :169 second signer anchor retrievable past index zero
- :192 revocation recorded immediately; :203 idempotent; :212 divergence
Where consumed: dispatch_test.zig, verify_test admission, pilot_test e2e,
adversarial_live/semantic (initDurableLedger consumers inherit).
