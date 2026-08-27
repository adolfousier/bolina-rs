# main.zig -> bin/bolina (W5)

Source: `src/main.zig` (269 lines). Entry + env config + boot order + signal handling. NO direct unit tests (covered by live smoke: curl suite + pilot e2e) - Rust port gets an integration-style smoke replicating the P1/P2 curl ladder.

## Entry point

`pub fn main(init: std.process.Init) !void` (main.zig:115). Zig 0.16 argv via init iterator; CLI dispatch to ca_cli.maybeRun FIRST. Rust: std::env::args, no argsAlloc analog needed.

## Env config surface (all optional except semantics below)

| Var | Default | Fatal on |
|---|---|---|
| BOLINA_BIND | 0.0.0.0:7420 | EADDRINUSE = process exits loudly |
| BOLINA_DATA_DIR | ~/.bolina | unwritable at key load |
| BOLINA_LEDGER | $DATA_DIR/ledger.bin | - |
| BOLINA_RESOURCES | empty | malformed entry (strict `bol:<16hex>/<ns>/<id>`) = boot refusal, never skip-and-continue |
| BOLINA_CONTROL | absent=off | bind failure fatal when present |
| BOLINA_TEST_CA | dev-only, must be ABSENT in release builds | - |

## Boot order (fixed sequence)

keys load-or-generate (D-018) -> durable ledger open (flock exclusive) -> Dispatch wire (initDurableLedger, intent Table capacity) -> Control plane attach (token file 0600, hex printed ONCE; fingerprint printed is hex ALREADY - the double-hex bug was fixed, keep it single) -> signals armed.

## Signals

SIGINT=2 / SIGTERM=15 (:45-46) -> graceful drain bounded -> ledger close -> exit 0 ("shutdown complete, ledger consistent"). Rust: no tokio; signal handling matches single-thread poll loop design (E4 rule).

## Caps / plumbing consts

MAX_DGRAM=2048 (:31), SA_LEN=28 (:32), CLOCK_REALTIME Timespec extern (:54-55) - the flat-libc seam pattern carries to Rust as the single audited extern block.

## Required Rust tests (integration style, named identically to the recorded smokes)

- healthz 200 without token; bearer gate 403 on /v1/*; chunked -> 501
- POST intent happy 202 + retry idempotent (counter stays 1) + conflict 409 + foreign-fp 422 + malformed 400
- SIGTERM under load drains and closes cleanly
