# daemon.zig contract sheet (src/daemon.zig, 342 lines)

## Contract
Single-threaded node core: one poll() slotmultiplexes wire UDP + optional TCP
control listener + client slots. Zero threads, EVER (E4 rule). Owns keys
(loadOrGenerate), HandshakeServer, session SessionTable, durable ledger
(initDurableLedger), Dispatch, intent Table, optional Control.

## Wiring map (cites)
- Boot order: keys.zig loadOrGenerate -> ledger initDurableLedger -> Dispatch.init
  -> Daemon struct storage STATIC (stable pointers for Control wiring!) ->
  optional Control attach via main.zig env (main.md sheet).
- handleTransport path: mac1 gate FIRST (3 rejection sites before ANY X25519,
  per noise.md) -> session lookup -> if !bound: binding frame verify via
  bindSession(remote_kex_pubkey,...) - the F1 signature, cert kex must EQUAL
  handshake static or KexPubkeyMismatch -> then envelopes.
- Types 5/6 relay-role-gated: role bits checked BEFORE service (relay_serve.md
  sender-gate inheritance); without RelayServe attached: silent DROP fail-closed.
- Response index layout type-2 MUST match SPEC 4.1a: offset 4 = responder's
  sender_index (its local slot), offset 8 = echo of initiator's announced index.
  The e4fd0d4 fix + byte-pin test (0xA70F1E kill: 'expected 10948382, found 0')
  is INHERITED MANDATORY in Rust integration tests - this bug survived 177
  mutants + vectors + fuzz; only live interop killed it. Port rule: consume the
  indices somewhere REAL so regressions cannot hide again.
- SIGTERM: drain bounded -> ledger flush -> exit; message "shutdown complete"
  invariant tested in pilot.
- Fail-closed default effect hook (D-064 R1): no ledger attached => effect
  refused, never best-effort.
- Effect orphan recovery: restart resumes executing intents via durable log
  (pilot e2e step 7).

## Env contract (from main.zig reads, normative names)
BOLINA_BIND | BOLINA_CONTROL(addr spec, opt-in, never default-on) |
BOLINA_DATA_DIR | BOLINA_LEDGER | BOLINA_RESOURCES comma-list canonical-only
(malformed= fatal boot error, declare-nothing = deny-all 422s) | BOLINA_TEST_CA
dev-only. EADDRINUSE is FATAL with clear message.

## Tests inherited
pilot_test.zig two-node ladder (handshake->binding both ways->intent->grant->
ledger commit->effect->restart->orphan recovery; negatives wrong-kex F1 +
intent replay); dispatch_test DAEMON_A-D families; adversarial_live S1.
