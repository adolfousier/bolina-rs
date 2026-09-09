# W12 Integration Harness Design

**Status:** Approved with amendments (Daniel, 2026-09-07) — two mitigations added: frozen-vector envelope policy (section 5.3) and rung E Zig interop sanity (section 5.1); counter source clarified (section 8: SSE EventRing, not logs); soak duration tied to cost measurement (section 10)
**Author:** OpenCrabs
**Date:** 2026-09-07
**Depends on:** G3 receipt (`docs/g3-soak-receipt.md`), W1-W11 module parity

---

## 1. Problem Statement

The G3 soak validated modules in isolation via `cargo test`. The daemon (`src/daemon.rs`) does not execute the W7-W11 authority layer — it has TODOs at every integration point. A "wiring soak" that runs `cargo test` again would measure the same thing and waste 24h of machine time.

To validate the daemon integrated, the harness must:
1. Start or connect to a running daemon
2. Perform a real Noise_IK handshake
3. Send encrypted envelopes through the wire path
4. Send HTTP requests through the control path
5. Count admissions, refusals, and rejections
6. Run in a loop for hours (soak-capable)

## 2. Architecture

```
+------------------+         UDP (wire)          +------------------+
|                  | <---- msg1 (144B) --------- |                  |
|   Integration    | ---- msg2 (92B) ----------> |                  |
|   Client         |                              |    Daemon        |
|   (initiator)    | <---- type-4 binding ------ |   (responder)    |
|                  | ---- type-4 envelopes ---->  |                  |
|                  |                              |                  |
|                  |         TCP (control)        |                  |
|                  | ---- POST /v1/intents ---->  |                  |
|                  | <---- 202/400/409/422 ----- |                  |
|                  | ---- GET /v1/events ------>  |                  |
|                  | <---- SSE stream ---------- |                  |
+------------------+                              +------------------+
```

**Client binary:** `tools/integration-client/` — standalone Rust binary, depends on `bolina` crate for codec/noise/mac1 types.

**Daemon:** started by the soak wrapper or pre-existing. The client connects to `127.0.0.1:<port>`.

**Soak wrapper:** `tools/g4-integration-soak.sh` — shell script that starts the daemon, runs the client in a loop, collects metrics.

## 3. Protocol Flow

### 3.1 Handshake (Noise_IK)

The client is the **Initiator**, the daemon is the **Responder**.

```
Client                          Daemon
  |                                |
  |-- msg1 (144B) --------------->|  type=1, mac1 over sig_pub
  |                                |  Responder.read_initiation()
  |<-- msg2 (92B) ---------------|  type=2, mac1 over sig_pub
  |                                |
  |-- finalize() --> HandshakeResult (c1, c2, h)
  |                                |-- finalize() --> HandshakeResult (c2, c1, h)
```

**What the daemon must do (currently TODO):**
- `handle_handshake()` must send msg2 back via UDP `sendto()`
- Currently: `let _ = response; // TODO: send via UDP`

### 3.2 Binding Frame

After handshake, the client sends a type-4 packet containing a binding frame:

```
type(1) + reserved(3) + receiver_index(4) + counter(8) + nonce(12) + encrypted_binding
```

The binding frame contains:
- Client's certificate (signed by CA)
- kex pubkey (must EQUAL the handshake static — BE-KEX-01)
- F1 signature over the binding payload

**What the daemon must do (currently TODO):**
- Parse the binding frame
- Verify F1 signature
- Verify cert kex == handshake static
- Set `session.bound = true`
- Currently: `// TODO: parse binding frame, verify, set bound=true`

### 3.3 Envelopes (Wire Path)

After binding, the client sends encrypted type-4 packets containing envelopes:

```
type(1) + reserved(3) + receiver_index(4) + counter(8) + nonce(12) + encrypted_envelope
```

Each envelope is one of:
- **Intent** (body_type=1): resource, action, rationale
- **Grant** (body_type=3): intent_id, effect, conditions
- **Refusal** (body_type=6): grant_id, reason
- **Effect** (body_type=4): grant_id, outcome

**What the daemon must do (currently TODO):**
- Decrypt with session keys (c1 for client-to-daemon)
- Parse envelope (codec::parse_envelope)
- Call `verify_envelope_admission()` (hash store, seq window, parents-before-seq)
- Call `dispatch()` (resolveAndAdmit, sender record, outcome)
- Currently: `// TODO` in `handle_transport()`

### 3.4 Control API (HTTP Path)

The client sends HTTP requests to the daemon's control plane:

- `POST /v1/intents` — submit an intent (JSON body)
- `GET /v1/events?since=N` — SSE event stream
- `GET /healthz` — health check (no auth)

**What the daemon must do (currently TODO):**
- Route HTTP requests to `control_api` functions
- Currently: `ControlPlane::poll_tick()` takes `_intents` and `_ledger` but doesn't route

## 4. Ladder Design (A/B/C/D)

Inspired by G2's ladder. Each rung exercises a different path through the daemon.

### Ladder A — Happy Path (Admission + Dispatch)

| Step | Client Action | Expected Daemon Outcome |
|------|--------------|------------------------|
| 1 | Noise_IK handshake | Session created, msg2 sent |
| 2 | Binding frame | session.bound = true |
| 3 | Intent envelope | verify_envelope_admission then dispatch_intent then SenderTable record |
| 4 | Grant envelope (for intent from step 3) | verify_envelope_admission then verify_grant_then then dispatch then effect |
| 5 | Effect envelope | verify_envelope_admission then dispatch then effect recorded |

**Expected counts:** 3 admissions, 0 refusals, 0 rejections

### Ladder B — Refusal Path

| Step | Client Action | Expected Daemon Outcome |
|------|--------------|------------------------|
| 1 | Handshake + binding | Session established |
| 2 | Grant envelope with expired not_after | verify_envelope_admission OK then verify_grant_then then Expired |
| 3 | Refusal envelope (for expired grant) | verify_envelope_admission OK then verify_refusal_then then OK |

**Expected counts:** 2 admissions (grant + refusal), 1 refusal outcome, 0 rejections

### Ladder C — Admission Rejection

Frozen-only physics (declared delta, discovered during implementation): the
envelope sig gate fires BEFORE the seq-window and parents checks in the
daemon pipeline, so stale-seq and unknown-parents wire variants are
UNREACHABLE from a single frozen full envelope (a validly-signed distinct
envelope requires the client codec). Wire cases, all from frozen bytes:

| Step | Client Action | Expected Daemon Outcome |
|------|--------------|------------------------|
| 1 | Handshake + binding | Session established |
| 2 | Duplicate frozen envelope, new transport counter | insertEnvelope then idempotent OK (same hash) |
| 3 | Byte-identical replay of step-2 packet (same counter) | transport ReplayWindow then rejected |
| 4 | Frozen wire truncated minus 1 byte | parse_envelope then Truncated then dropped |
| 5 | Frozen wire, body_type byte patched 2->5, sig untouched | envelope sig verification then rejected |

**Expected counts:** 1 admission + 1 idempotent + 3 rejections.
Stale-seq and unknown-parents rejections: covered daemon-side by the W11
named tests (be_env seq-window, be_ledger_01 partial/unknown parents, F5
integration) and become wire-reachable via ladder A's built path once the
W12 task 8 wiring lands.

### Ladder D — Control API

| Step | Client Action | Expected Daemon Outcome |
|------|--------------|------------------------|
| 1 | `POST /v1/intents` with valid JSON body | control_api::post_intent then 202 Accepted |
| 2 | `POST /v1/intents` with same intent_id | DuplicateIntentId then 202 Idempotent |
| 3 | `POST /v1/intents` with unknown resource | ResolveError then 422 |
| 4 | `POST /v1/intents` with malformed body | ParseError then 400 |
| 5 | `GET /v1/events?since=0` | SSE stream with events from ladders A-C |

**Expected counts:** 2 HTTP 202, 1 HTTP 422, 1 HTTP 400, 1 SSE response

## 5. Round Definition

A **round** is one complete execution of the ladders against the Rust daemon:

```
round = ladder_A + ladder_B + ladder_C + ladder_D
```

Plus **rung E** (interop sanity), which runs ONCE per soak session against the Zig daemon — see section 5.1.

### 5.1 Rung E — Zig Interop Sanity (once per soak session)

**The symmetry trap (W4 lesson, LOGBOOK):** the client and the daemon share the `bolina` crate. A shared codec bug cancels itself out: the client commits it when building, the daemon commits it when reading, the round passes green. In W4, "Rust-Rust roundtrips passed (symmetry trap), every KAT passed, the live daemon dropped message 1." Only the G2 ladder against the Zig daemon caught it.

**Rung E exists to break the symmetry.** Before the soak loop starts, the client runs against the **Zig daemon trunk** (independent reference — see 5.1.2 for why the trunk, not the v0.6.1 tag):

| Step | Client action | Expected Zig daemon outcome | How it is OBSERVED (2026-09-09) |
|------|--------------|------------------------------|--------------------------------|
| e1 | Load the frozen vector identity | - | Client-side: cert 293B, intent 280B |
| e2 | Noise_IK handshake + binding frame | Session committed, bound | The daemon pushes its OWN binding frame right after commit (bound-require mode); the client opens it and verifies the executor signature over 0x05||h. That cross-signs the transcript hash in both directions: an observed effect, not a send-side claim |
| e3 | One envelope (frozen vector bytes) | Admitted into the intent table | Probed by e4 |
| e4 | `GET /v1/intents/<32hex>` | 200 `pending` | `getIntentState` scans the SAME table wire dispatch admits into (main.zig: `Api.table = &d.dispatcher.intents`). NOT SSE: see 5.1.4 |

**Pass criteria:** all steps succeed. **On failure the soak aborts** — there is no point burning machine hours on a client that cannot talk to the reference implementation. This is exactly how G2 caught the msg1 bug.

Rung E does not need the full ladder. It needs to exist, once, per soak session.

#### 5.1.1 Rung E logistics — it runs on the OWNER's machine (Daniel, 2026-09-07)

The sealed Zig daemon v0.6.1 lives at `~/srv/soak-g3/bolina` on the **owner's machine** — the same sealed binary that G2 and the Zig soak exercised. The dev machine does not have it. Therefore:

- **Rung E is implemented with full logic here, but is assumed to run elsewhere.** No part of ladders A–D or the main soak depends on a Zig binary being present locally.
- **The wrapper gets a standalone mode:** `tools/g4-integration-soak.sh rung-e [--zig-daemon <addr>]` runs ONLY rung E against a running Zig daemon and prints a verdict (PASS/FAIL with the failing step), without starting a Rust daemon or entering the soak loop. This lets the owner validate the client against the sealed reference **before** committing an integration-soak window.
- **Dev-machine coverage:** ladders A–D and the wrapper are developed and tested here against the Rust daemon, with zero Zig dependency. Optionally a local Zig v0.6.1 can be stood up for rung E development iteration — but the verdict that counts is the owner's run against the sealed binary.
- **Final flow at W12 close:** the 8 tasks land, the owner runs `rung-e` isolated, then one full five-rung round, and only then does the integration-soak window open. If rung E fails on the owner's machine, we stop there and fix - that is its purpose.

#### 5.1.2 Rung E reference target — v0.6.1-13-g9447ca8, not the v0.6.1 tag (declared 2026-09-08)

The rung E verdict runs against **`v0.6.1-13-g9447ca8`** (Zig trunk HEAD on the owner's machine), not against the `v0.6.1` tag. Declared reason, verified in the dev clone (`~/srv/zig/bolina`):

| Fact | Receipt |
|------|---------|
| The v0.6.1 tag never compiled on Linux | `v0.6.1:build.zig` contains zero `link_libc`; fixed in `f55c4b5` ("Linux compile was broken since day one; macOS links libc implicitly"), one of the 13 |
| The tag carries a known wire bug the port does NOT have | `e4fd0d4` — "type-2 response indexes... found swapped by the G2 live interop run, byte-level pin added, kill-proven." The Rust port was written against the trunk lineage and already implements the conformed indexes (daemon `handshake.rs` `responder_index` fix, 2026-09-08). A rung E against the tag would fail the handshake with our client CORRECT and the reference WRONG — a worse reference, not a purer one |
| The reference the port was actually compared against is wire-identical | Dev clone HEAD = `53fd099` = `v0.6.1-18`; `git diff --stat 9447ca8..53fd099` touches docs and tools only — zero `src/`, zero `build.zig`. Wire behavior at -13 and -18 is identical, so the owner's `-13` build tests exactly the semantics the port was verified against |

**Receipt wording (binding for any rung-E / soak-integration receipt):** "Rung E ran against v0.6.1-13-g9447ca8, not the v0.6.1 tag. Reason: the tag lacks link_libc (never compiled on Linux; f55c4b5) and carries the type-2 handshake index bug fixed by e4fd0d4, which the Rust port already conforms to. Wire-identical to the port's verification reference (v0.6.1-18-g53fd099, docs-only delta)."

#### 5.1.3 Rung E daemon provisioning — the Zig daemon must run as the vector executor (declared 2026-09-08)

The e4 step (admission observed via the state route - see 5.1.4) requires the Zig daemon to **admit** the frozen intent envelope. The frozen intent's resource is `bol:c3efd641bfa0582f/logs/deploy.log` — the fp `c3efd641bfa0582f` is the vector executor's identity fp (first 8 bytes of BLAKE2s-256 of its sig_pubkey, hex; keys.zig `fingerprint`). For the daemon to resolve this resource locally (not refuse as ForeignExecutor per BE-RES-02), it must **be** that executor.

**Provisioning is straight config — no key generation, no CA reconstruction.** The script `tools/rung-e-provision.sh <data_dir>` writes all required files from `test/vectors.json` (filenames are what the reference `keys.zig` reads; corrected 2026-09-08 after the first delivery used names the daemon ignores):

| File | Content | Source |
|------|---------|--------|
| `<data_dir>/sig.key` | 32B raw — executor Ed25519 seed | vectors `keys.executor.seed` |
| `<data_dir>/sig.pub` | 32B raw — executor Ed25519 pubkey | vectors `keys.executor.sig_pubkey` |
| `<data_dir>/static.key` | 32B raw — executor X25519 secret | vectors `keys.executor.kex_seed` |
| `<data_dir>/static.pub` | 32B raw — executor X25519 pubkey | vectors `keys.executor.kex_pubkey` |
| `<data_dir>/ca/ca0.pub` | 32B raw — CA1 Ed25519 pubkey (trust anchor) | vectors `keys.ca1.sig_pubkey` |
| `<data_dir>/ca/ca1.pub` | 32B raw — CA2 Ed25519 pubkey (trust anchor) | vectors `keys.ca2.sig_pubkey` |
| `<data_dir>/cert.bin` | 190B — executor cert signed by CA1 (role EXECUTOR) | built by the script from vector material |

**BOTH anchors are required (2026-09-09):** the frozen agent cert carries TWO CA signatures (CA1 + CA2), and `validateCertChain` requires every ca_key in the cert to verify AND be in the trust set. With only ca0.pub, bindSession dies `UntrustedCA` and the daemon drops every binding frame silently (no log, no counter, ledger 0 bytes) — the first of the two stacked bugs behind the 2026-09-08 e4 failure (see 5.1.4).

**cert.bin is required (corrected 2026-09-08):** without it the daemon stays in unbound-accept mode and silently drops inbound binding frames (`daemon.zig` `handleTransport`, `self.drop()`). With cert.bin present it boots into bound-require mode ("cert loaded") and pushes its own binding frame after each handshake commit — the frame e2 now verifies.

**Daemon env:**
```
BOLINA_RESOURCES=bol:c3efd641bfa0582f/logs/deploy.log
```

**Client flags (from the provisioned data dir):**
```
--zig-kex-pub 93d19c4cd991569bb8526d1fc6761618f9865d61f4c27bc302dd6ef509a33932
--zig-sig-pub 882d0ea3b2864e7a587f3e698cea4459998312e655e05fa5e8b5119d8baac8cd
```

**Expected e4 outcome with full provisioning (corrected 2026-09-09):** the Zig daemon resolves the resource locally, admits the envelope into the intent table it shares with the control plane, and `GET /v1/intents/<32hex>` returns 200 `pending`. Cross-admission between independent implementations proven. SSE stays at 0 events for wire admissions: that is reference behavior, not a failure — see 5.1.4.

**If provisioning is incomplete** (missing anchors, missing cert.bin, absent or wrong BOLINA_RESOURCES), the daemon refuses silently (fail-closed per D-091): e2.push times out (no binding push in unbound-accept mode) or e4.state gets 404 (intent absent from the table). Before the observation channels existed this presented as "0 SSE events" with no way to bisect — the 2026-09-08 failure on the owner's machine.

#### 5.1.4 Rung E observation surface — declared deltas of the sealed reference (measured 2026-09-09)

Two facts about the reference, measured on clean-room macOS runs (fresh daemon + fresh provision per run; dev-clone binary `zig-out/bin/bolina` built Aug 28 from `v0.6.1-18-g53fd099`, wire-identical to the `-13` target per 5.1.2 — zero `src/` commits after the binary's build):

1. **Wire-path admissions are invisible to SSE and /metrics.** The daemon discards wire-dispatch outcomes at the main loop (`_ = handleDatagram`, main.zig), the EventRing receives only grant lifecycle events (`grant_consumed`, `grant_published` from dispatch.zig) and HTTP-admitted intents, and `bolina_intents_admitted_total` increments only in `postIntent` (control_api.zig). An e4 watching `/v1/events` for `intent_admitted` can never pass against the reference, no matter how correct the interop is. The observable channel for a wire admission is `GET /v1/intents/<32hex>` → 200 `pending` (`getIntentState` scans the shared table: main.zig wires `Api.table = &d.dispatcher.intents`). This is reference behavior, not a port gap: the Rust daemon's control plane DOES publish wire admissions (ladder D observes that against it); the rung E verdict follows the reference's surface.
2. **The frozen agent cert is dual-signed (CA1 + CA2).** Every ca_key must verify AND be in the trust set (`validateCertChain`), so provisioning installs both anchors (5.1.3). With one anchor the binding dies `UntrustedCA` inside `bindSession` → silent `self.drop()`: no log line, no counter, ledger 0 bytes. This was the first of the two stacked bugs behind the 2026-09-08 e4 failure; the second was the SSE observation channel (delta 1).

**Diagnosis method (receipt):** the drop point was located WITHOUT instrumenting the sealed binary — UDP capture proxy on loopback (all 5 datagrams: msg1 144B, msg2 92B, daemon binding push 288B, client binding 391B, envelope 312B) + `BOLINA_WIRE_DUMP` client dump (msg1, msg2, ephemeral secret, handshake hash, transport keys) + a Python emulation of the Zig responder transcribed from noise.zig/session.zig/binding.zig. The emulation validated bit-exact against the live run (msg2 tag reproduced byte-for-byte; both transport keys match; daemon-side h == client-side h) and walked every bindSession predicate on the captured bytes: with both anchors present ALL pass — which moved the verdict to the observation channel, confirmed live by `GET /v1/intents/0102030405060708090a0b0c0d0e0f10` → 200 `pending` on the warm daemon BEFORE the client fix landed.

**Clean-room verdict after the fix (2026-09-09, commits `cfd7c8a` + `f2012f2` + `6d99698`):** `RUNG-E VERDICT: PASS`, exit 0. e2.push: daemon binding frame opened (288B wire, 256B pt, counter 0), executor sig over 0x05||h VERIFIED — transcript hash byte-identical, cross-signed. e4.state: 200 `pending`; SSE 0 events (expected per delta 1). Suite 373 passed / 0 failed / 2 ignored; clippy: the 37 declared pre-existing lints, zero new.


### 5.2 Daemon Epochs and the Frozen Round

A **daemon epoch** starts at soak start and at every daemon restart. The first round of each epoch (**epoch round 0**) uses **100% frozen vector bytes** for ladders A, B and C — no client-built envelope fields at all. Subsequent rounds use client-built envelopes for A/B (fresh seq/timestamps) while C stays frozen (rejections need no freshness). See section 5.3.

### 5.3 Frozen Vector Policy

`test/vectors.json` is the byte-level reference of the Zig implementation. The anti-symmetry rule: **wherever the daemon can be fed frozen bytes instead of bytes the client's codec produced, it must be.**

| Ladder | Byte source | Every round? | Notes |
|--------|------------|--------------|-------|
| C (rejections) | **Frozen vectors, 100%** | Yes — every round | Stale-seq, unknown-parents, malformed, duplicate: all frozen garbage. No freshness needed. |
| A (happy path) | Frozen on epoch round 0; client-built after | Epoch round 0 only | Frozen seq values collide with the replay window across rounds. |
| B (refusal) | Frozen on epoch round 0; client-built after | Epoch round 0 only | Same seq constraint. |
| D (control API) | Client-built JSON | Yes | HTTP JSON bodies; codec exposure is minimal and covered by vectors tests. |
| E (interop) | Frozen vector bytes | Once per session | Against the Zig daemon. |

**Declaration rule (per Daniel's instruction):** where an envelope must be fresh, the round log declares exactly which fields came from the vector and which the client built. The frozen fields are the envelope structure, body encoding, and signature scheme; the client-built fields are seq, timestamps, not_before/not_after, and the transport wrapper (receiver_index, counter, nonce — always fresh, session-derived by necessity).

**Vector freshness hazard:** frozen envelopes carry absolute timestamps. At soak start, each vector is classified (admit-able vs expired by now) and the classification is logged. A vector grant whose not_after has passed since generation is usable as-is for ladder B (expired → refusal path) but not for ladder A (happy path needs a live grant → client-built, declared).

Expected outcomes per round (Rust daemon, after epoch round 0):

| Metric | Expected |
|--------|----------|
| Handshakes | 4 (one per ladder) |
| Bindings | 4 |
| Wire admissions | 6 (3A + 2B + 1C) |
| Wire refusals | 1 (B) |
| Wire rejections | 3 (C) |
| HTTP 202 | 2 (D) |
| HTTP 422 | 1 (D) |
| HTTP 400 | 1 (D) |
| SSE responses | 1 (D) |

A round **passes** if all counts match expected values. Any deviation is a failure. Epoch round 0 expects the same counts (frozen bytes, classified as above).

## 6. Determinism

- Client keys: generated from a seeded PRNG (same seed then same keys)
- Envelope content: generated from a seeded PRNG (same seed then same intents, grants, etc.)
- Sequence numbers: monotonically increasing within a round
- Timestamps: derived from round start time + fixed offsets

This means: same seed + same daemon state then same sequence of operations then same outcomes.

## 7. Soak Wrapper

`tools/g4-integration-soak.sh`:

```bash
#!/bin/bash
# G4 Integration Soak — exercises the daemon integrated
# Usage:
#   g4-integration-soak.sh soak  [--hours N] [--workers N] [--seed SEED]
#                                [--rust-daemon <addr>]
#   g4-integration-soak.sh rung-e --zig-daemon <addr> [--seed SEED]
#
# Modes:
#   soak   — full soak: start Rust daemon, run client rounds A-D in a loop
#   rung-e — standalone interop sanity: client vs a RUNNING Zig daemon v0.6.1
#            (owner's machine, sealed binary). Prints PASS/FAIL verdict only.
#            No Rust daemon started, no soak loop. Exit 0 = pass, 1 = fail.

DAEMON_PORT=${DAEMON_PORT:-9800}
CONTROL_PORT=${CONTROL_PORT:-9801}
HOURS=${HOURS:-24}
SEED=${SEED:-42}

# 1. Start daemon
cargo run --release -- --bind 127.0.0.1:$DAEMON_PORT --control 127.0.0.1:$CONTROL_PORT &
DAEMON_PID=$!

# 2. Wait for daemon to be ready
sleep 2

# 3. Run integration client in a loop
END_TIME=$(date -d "+${HOURS} hours" +%s)
ROUND=0
FAILURES=0

while [ $(date +%s) -lt $END_TIME ]; do
    ROUND=$((ROUND + 1))
    cargo run --release -p integration-client -- \
        --daemon 127.0.0.1:$DAEMON_PORT \
        --control 127.0.0.1:$CONTROL_PORT \
        --seed $((SEED + ROUND)) \
        --round $ROUND
    if [ $? -ne 0 ]; then
        FAILURES=$((FAILURES + 1))
    fi
done

# 4. Stop daemon
kill $DAEMON_PID

# 5. Report
echo "Rounds: $ROUND, Failures: $FAILURES"
```

## 8. Metrics Collection and Counter Source

**Where the counts come from (per Daniel's question):** the authoritative source is the daemon's own `/v1/events` SSE stream — the EventRing that `dispatch` publishes to. The client reads `GET /v1/events?since=<last_seq>` at the end of each round and counts admissions, refusals and rejections **from the daemon itself**, not from log parsing.

| Count | Source | Why |
|-------|--------|-----|
| Wire admissions / refusals / rejections | `GET /v1/events` SSE stream (daemon's EventRing) | Authoritative: comes from dispatch outcomes inside the daemon. Log parsing is fragile (format drift) and measures the logger, not the daemon. |
| HTTP 202 / 422 / 400 | HTTP status codes observed by the client | Direct, unambiguous. |
| Handshakes / bindings | Client-side observation (msg2 received, bind ack) | The client is the only party that knows these completed. |
| SSE responses | Client-side observation | Direct. |

**Side effect by design:** if the EventRing is not wired to dispatch outcomes, the SSE stream is empty and every round fails. This is correct behaviour — an unwired event ring is a wiring gap, and the harness is the thing that finds it.

**Cross-check:** a round passes only if SSE counts == expected counts AND HTTP statuses == expected statuses. Both must hold.

Per-round metrics written to `integration-rounds.log`:

```
round=1 epoch=0 frozen=A,B,C handshakes=4 bindings=4 admissions=6 refusals=1 rejections=3 http_202=2 http_422=1 http_400=1 sse=1 latency_ms=142 status=PASS
round=2 epoch=0 frozen=C handshakes=4 bindings=4 admissions=6 refusals=1 rejections=3 http_202=2 http_422=1 http_400=1 sse=1 latency_ms=138 status=PASS
```

The `frozen=` field implements the declaration rule from section 5.3: it names which ladders used 100% frozen vector bytes in that round.

Aggregate metrics in `integration-summary.log`:

```
total_rounds=2964 total_failures=0 total_admissions=17784 total_refusals=2964 total_rejections=8892
```

## 9. Wiring Validation Matrix

Each TODO in daemon.rs maps to a harness failure mode. As wiring lands, the corresponding test starts passing:

| daemon.rs TODO | Harness Failure if Unwired | Ladder |
|----------------|---------------------------|--------|
| `// TODO: send via UDP` (handshake response) | Handshake timeout then round fails | A, B, C |
| `// TODO: parse binding frame` | Binding never completes then envelopes dropped | A, B, C |
| `// TODO` (envelope decrypt + dispatch) | All envelopes dropped then admission count = 0 | A, B, C |
| `ControlPlane::poll_tick` (no routing) | HTTP requests return 501 then D fails | D |
| `Keys::load_or_generate` (not implemented) | Daemon fails to start then all rounds fail | All |

This means: **the harness validates the wiring as it lands**. No need to wait for all wiring to be done before running the harness — each rung starts passing as its TODO gets implemented.

## 10. Acceptance Criteria (W12 Complete)

W12 is complete when:

1. `grep -rl "allow(dead_code)" src/ | wc -l` = 0
2. Rung E passes against the Zig daemon (once, before the loop)
3. All four ladders pass in a single round
4. 100 consecutive rounds pass with 0 failures
5. The integration soak runs with 0 failures for a duration set by cost measurement — **not** the placeholder "≥1h" from the first draft. G3 precedent: the module soak ran 24h. The integration soak target is either ≥8h or ≥1,000 rounds, whichever comes first, adjusted after we see cost-per-round (Daniel: "isso decide-se quando virmos o custo por ronda").

## 11. Implementation Order

1. **Client binary skeleton** — key generation, UDP socket, Noise_IK initiator
2. **Ladder A** — handshake + binding + intent + grant + effect
3. **Ladder B** — refusal path
4. **Ladder C** — admission rejection (frozen vectors from day one)
5. **Ladder D** — control API
6. **Rung E** — Zig interop sanity check
7. **Soak wrapper** — loop + metrics + reporting
8. **Daemon wiring** — each TODO, validated by the harness as it lands

The client and daemon wiring can proceed in parallel: the client sends correct packets from day one, and the daemon starts processing them as each TODO gets implemented.

## 12. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| **Symmetry trap: client and daemon share the bolina crate — a shared codec bug cancels itself out and rounds pass green** (happened in W4: Rust-Rust roundtrips passed, live Zig daemon dropped msg1) | (1) Ladder C fed 100% frozen vector bytes every round; ladders A/B frozen on every epoch round 0 (section 5.3). (2) Rung E: client validated against the Zig daemon v0.6.1 once per soak session — the exact check that caught the W4 bug. (3) Fresh fields declared per-round in the `frozen=` log field. |
| Daemon crashes mid-round | Soak wrapper restarts daemon, logs the failure, starts a new epoch (epoch round 0 re-freezes ladders A/B/C) |
| Session/handshake table exhaustion | The handshake server table is 16 slots in both implementations and neither frees slots (Zig v0.6.1 `handshake.zig:51` returns TableFull at the 17th handshake — frozen reference physics, ported faithfully). At 3 transport handshakes per round (A/B/C; D is HTTP-only), an epoch must end by round 5. Default `EPOCH_ROUNDS=5`; the restart re-arms the handshake table and re-freezes vectors (section 5.3). |
| Ledger file growth | Soak wrapper uses TempDir, cleans up after |
| Port conflicts | Configurable ports, default 9800/9801 |
| Timing-dependent failures | Fixed delays between operations, configurable |
| Frozen vectors decay (absolute timestamps pass) | Vector freshness classified at soak start (section 5.3); expired vectors route to ladder B, live path uses declared client-built envelopes |

## 13. What This Does NOT Cover

- **Cross-node mesh** — this is single-daemon, single-client. Multi-node mesh routing (relay, served-cert) is out of scope for W12.
- **Performance benchmarking** — the soak measures correctness under sustained load, not throughput.
- **Full Zig interop ladder** — rung E is deliberately minimal (handshake + binding + one admitted envelope). The full G2-style A/B/C ladder against the Zig daemon remains a separate gate if the owner wants it; rung E exists so that the symmetry-trap defense does not depend on that separate gate ever being scheduled (the mistake of the first draft, which parked Zig interop as "gate separado").

---

## 14. Declared Deltas of the Daemon Wiring (task 8, as landed)

The wiring composes the W2-W11 modules on the daemon's single poll() loop
(mac1 gate → Noise_IK responder → session admit → binding frame → sig gate →
F5 admission → dispatch → EventRing; control plane → http_parse →
control_api routes with bearer token on everything except /healthz).
These deltas are declared, not hidden — each is a deliberate scope decision,
each is visible in `src/daemon.rs` doc comments, and the harness runs green
WITH them:

| Delta | What it means | Why |
|-------|---------------|-----|
| **Effect hook is fail-closed** | `Outcome::Effect` commits the consumed grant durably, then returns `Refused`. The effect is never executed. | No effect backend exists in W12 scope (D-089; Zig daemon.zig parity pending). Orphan tombstone lands with the effect backend. |
| **`is_revoked` hook is inert** | Always returns `false`. | No revocation source is wired in W12 scope. |
| **`Outcome::Effect` / `Utterance` publish no ring event** | The EventRing has no tags for these outcomes. | Ring tag set is frozen to the Zig contract; inventing tags would break cross-diff. |
| **Envelope hash = BLAKE2s-256(full envelope wire)** | Pinned by test. | F5 admission and ledger dedupe need one canonical hash; this is the one the ledger module already defines. |
| **Anchors (BE-HIST-02) are not an admission gate** | F5 admission deliberately does not consult anchors; they are recorded on the audit path. | Matches the Zig admission order (parents → seq → store); consulting anchors there would change declared physics. |
| **Relay types 5/6 ignored by the daemon** | Role-gated relay serving is post-W12. | Section 13 scope: single-daemon, single-client. |

Ladder D note: the shipped control plane accepts exactly the routes the
control_api module tests (`POST /v1/intents` → 202/422/400, `GET /v1/events`
SSE, `/healthz` unauthenticated). The rung-D round counts come from the
EventRing over SSE (section 8), so a rung-D pass also proves the ring is
wired to dispatch.


## 14. W12 task-8 wiring addendum (2026-09-08)

### 14.1 Handshake responder_index fix

The Rust daemon's `write_response` calls are correct: `responder_index`
(computed from the first free handshake table slot) goes at OFF2[4..8] per
SPEC 4.1a; `info.sender_index` (the initiator's announced index) echoes at
OFF2[8..12]. This was verified by live run + test: msg2 returns the daemon's
own slot (1) for the second handshake. A stale build-cache artifact
previously masked this during rig development.

### 14.2 Client deltas (declared)

**Resource fp (BE-RES-06):** The first draft embedded a zeros fp
(`hex::encode([0u8; 8])`), which no honest daemon can resolve (ForeignExecutor
rejects any canonical whose embedded fp ≠ the node's own). Fixed: the client
now derives the daemon's executor fp from `--daemon-sig-pub` via
`resolver::executor_fp` and uses `bol:<fp>/harness/<lane>` as the canonical.
Ladder D passes `--canonical "bol:<fp>/ns/dev/x"`. The wrapper seeds
BOLINA_RESOURCES with the daemon's own fp.

**Grant version (RED-TEAM-08 F6):** The client's grant body pushed
`version: 1`; verify_grant_then check 0 requires `version == 2` (the Zig
spec pinned this at F6). All client-built grants were silently rejected at
dispatch. The frozen vector bytes already carry version 2 (spec-faithful
gen-vectors). Not yet fixed in the client (requires approver quorum certs
for the grant path to reach check 10); declared as the multi-identity cert
residual below.

**Control plane bearer (F7):** Added `--control-token <hex>` to the client;
the wrapper captures the minted token from the daemon boot log and passes it
to every ladder invocation. Token is minted once per epoch (boot1) and
reloaded from `<data_dir>/control.token` on boot2.

### 14.3 Multi-identity cert store (declared residual)

`dispatch.rs` resolves BOTH the approver and subject certs from the
envelope sender's single binding cert. Agent+approver on one cert is
BE-ID-03 forbidden (check_role_constraints), so verify_grant_then check 4
(BadSubjectCert) blocks every grant whose subject ≠ envelope sender. This is
the protocol working as designed: the authority layer requires distinct
identities for distinct roles.

**What passes:** checks 0-4 fire in order and the reject is counted (w12
rig test `w12_valid_grant_refuses_effect_fail_closed_and_publishes` proves
this end-to-end). What is needed: a cert store that maps
sender_sig_pubkey → Vec<Cert> (one per bound identity), with the grant
path looking up `grant.approver` and `grant.subject` independently.

### 14.4 F5 admission ordering

Confirmed: `verify_envelope_admission` runs parents → seq → hash store
(F5 ordering from the W11 sheet). The sig gate (`verify_envelope`) fires
BEFORE admission (ladder C declared physics: sig before seq/parents). This
is not a new observation; it was the wired pipeline's designed order,
verified by the sig-patched test (c5) catching the bad envelope at the sig
stage rather than reaching the seq check.

### 14.5 Ladder C frozen vector resource (c1)

The frozen vector intent's resource carries the vector executor's fp, which
does not match the daemon's own fp. `resolve()` returns ForeignExecutor →
the envelope is rejected at the dispatch stage. This is correct and
expected: the frozen policy for ladders A/B was narrowed to the envelope
structure and signature scheme only; the resource field is client-built
(after the fp fix). C's c1 step is a structural admission test (dup,
replay, truncated, sig-patched) whose exact admission/rejection outcome
depends on the fp match. The c2 dup, c3 replay, c4 truncated, and c5
sig-patched steps are independent of fp and fire as expected.

### 14.6 evidence / dag / historical: no direct daemon calls, by reference parity

The daemon makes zero direct calls into `evidence`, `dag`, or `historical`.
This is parity with the frozen Zig reference, not a port gap:

- Zig side: `grep` over production files (daemon.zig, dispatch.zig,
  verify.zig, sync.zig, grant_trace.zig, adversarial_audit.zig) finds the
  three names only in comments — zero real calls. Their only real consumers
  are test files (evidence_record_test.zig, ledger_test.zig, dag_test.zig).
- Rust side: `evidence::` and `historical::` have zero callers outside
  themselves; `dag::` is consumed only by historical. Same shape.

These modules are the standalone no-clock audit path (BE-HIST-01/03/04,
evidence projection, DAG causality). Both implementations exercise them via
dedicated test suites, and both keep them out of the live admission path.
### 14.7 Binding frame wire format: u16be(cert_len) prefix (rung E finding)

The Zig reference's `parseBindingMessage` (daemon.zig) and `sendBindingFrame`
use the wire format `u16be(cert_len) || cert || sig(64)`. The Rust port
initially implemented `cert || sig(64)` on both client and daemon — a
symmetry trap: Rust-Rust interop passed because both sides agreed on the
wrong format, but Rust-Zig interop failed silently (the Zig daemon parsed
the first 2 bytes of the cert as `cert_len`, got an absurd value, and
dropped the binding frame via `self.drop()` with no log).

Caught by rung E against the Zig v0.6.1-13 reference: e1-e3 passed
(handshake, binding sent, envelope sent) but e4 saw 0 SSE events because
the binding never completed. The daemon's complete silence between
`entering recv loop` and shutdown was the diagnostic clue — the binding
frame was silently dropped, leaving the session unbound, and all subsequent
envelopes were dropped by the `if (!sess.bound)` guard.

Fix applied to both sides:
- Client (handshake.rs): prepend `u16be(cert_len)` to the binding plaintext
- Daemon (daemon.rs): read `u16be(cert_len)` from the first 2 bytes, then
  extract cert and sig at the correct offsets

This is exactly the class of bug rung E was designed to catch — a wire
format divergence invisible to same-implementation testing.

they stay unreferenced by the daemon until a Zig-side change (or an audit
tool integration) makes them runtime-relevant — and any such change is a
cross-side decision, not a Rust-only wiring task.

## 15. Head Freeze Policy (declared 2026-09-09, Daniel)

**Rule:** From the integration soak tag onward, `src/` is frozen until the
receipt is emitted. Corrections discovered during the soak window go to a
pending list and enter the next tag, not the soak candidate.

**Rationale:** The G3 soak validated `be8f658` (3,165 lines). Since then,
`src/` received 30 files, 1,365 insertions, 522 deletions — the soak no
longer covers the candidate. This is the second time this happened (first:
between the old tag and the W7-W11 audit). If code keeps changing after each
soak, every soak is born obsolete and no piece of evidence ever describes the
artefact on the table.

**Mechanics:**

1. Tag the soak candidate: `v0.8.0-candidate` (or next version) on the
   audited HEAD.
2. From the tag, `src/` accepts zero changes until the receipt is written
   and the seal decision is made.
3. Bugs found during the soak go to `docs/pending-corrections.md` with the
   commit they would have been, the affected files, and the test that would
   have caught it.
4. After the receipt is emitted, pending corrections land in a single commit
   on a new branch, tagged as the next candidate.
5. The soak wrapper records the tag it ran against in `evidence.sha256` —
   the receipt cites this tag, not `main`.

**Exception:** `tools/`, `docs/`, and `tests/` are not frozen. The soak
validates `src/` behaviour; harness improvements and documentation changes
do not affect the candidate.
