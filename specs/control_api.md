# control_api.zig contract sheet (src/control_api.zig, 339 lines)

## Contract
The /v1 facade over dispatch internals. ANTI-GOD-MODE by construction: NO
direct ledger writes, NO grant mutation - postIntent routes through the SAME
resolveAndAdmit the wire path uses (sheet dispatch.md). F16 identity binding:
subject is REQUIRED hex64; missing = 400; forged subject dies later at wire
checks 4/6 with UnknownSender-family refusals, NEVER silently.

## Public surface (cites)
- consts: RING_CAP=256 :21, ID_HEX_LEN=64 :22, BODY_MAX=4096 :23,
  SUBJ_HEX_LEN=64 :70.
- EventTag enum(u8) :27 w/ .name() :32 (SSE tag strings are wire-visible;
  keep exact spelling).
- EventRing.publish drop-oldest-when-full ring :58; sequence numbers survive
  eviction; off-by-one pinned: 263 publishes in 256-ring => oldest survivor
  seq 8 (test asserts 8, NOT 9 - commit b4b94e7 note).
- ApiError :72: BadRequest, NotFound, MethodNotAllowed, UnsupportedMediaType,
  UnprocessableIntent + inner passthroughs. Rust: exhaustive enum, no String
  variants (D-049 analog).
- postIntent(body, out, now_ms) IntentOutcome :115: parse flat JSON ->
  validate id(32hex)+resource(canonical bol: form)+action+rationale+SUBJECT
  required -> resolveAndAdmit -> record SenderEntry -> metrics admitted_total++
  only on THIS HTTP path (wire admissions do NOT bump it - G2 finding #1).
  Responses: 202 accepted / 202 IDEMPOTENT on DuplicateIntentId (retry-safe,
  counter frozen at 1) / 409 ResourceHeld / 422 unknown+ambiguous+FOREIGN fp /
  400 body/shape errors (F5 table).
- getIntentState(id_bytes) :180 -> pending/executing/rejected/done lookup.
- metricsBody(out, ctl_requests, ctl_auth_refused, ctl_timeouts) :198:
  Prometheus text format; counter names pinned incl. control-plane trio from
  args (NOT globals) because wire-path passes real totals here.
- eventsSseBody(out, since) :224: cursor = durable ledger offset concept,
  replay paginated; parseSince(target) :249 strict digits-or-error.
- parseIdHex(hex*const [64]u8) ?[32]u8 :298.

## Invariants
- Flat hand-rolled JSON key extractor IS a known accepted limitation
  (THREAT-MODEL 4.11): first-match substring, loopback+bearer caller trusted.
  DO NOT "improve" to full JSON parser without revisiting that decision entry;
  promotion beyond loopback requires conscious re-decision (M-level).
- Every response byte format is asserted in tests; SSE lines end \n\n.

## Tests inherited (10, src/control_api_test.zig)
Happy admit+recordSender created / duplicate-id idempotent + single entry /
ResourceHeld 409 / foreign fp 422 / malformed 400 set / intent state polling /
metrics counters verbatim / SSE empty honest since=0 / parseSince rejects
non-digits / ring off-by-one seq-8 assert. G2 live finding folded: GET
/v1/intents/<id>->pending is THE proof of wire-side admission (admitted_total
stays 0 for wire).
