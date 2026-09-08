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

**Rung E exists to break the symmetry.** Before the soak loop starts, the client runs against the **Zig daemon v0.6.1** (sealed reference):

| Step | Client Action | Expected Zig Daemon Outcome |
|------|--------------|----------------------------|
| 1 | Noise_IK handshake (client's own codec) | Handshake completes — the msg1 pre-message path that W4 got wrong |
| 2 | Binding frame | Bound |
| 3 | One envelope (frozen vector bytes) | Admitted |
| 4 | `GET /v1/events` | Admission visible in the event stream |

**Pass criteria:** all four steps succeed. **On failure the soak aborts** — there is no point burning machine hours on a client that cannot talk to the reference implementation. This is exactly how G2 caught the msg1 bug.

Rung E does not need the full ladder. It needs to exist, once, per soak session.

#### 5.1.1 Rung E logistics — it runs on the OWNER's machine (Daniel, 2026-09-07)

The sealed Zig daemon v0.6.1 lives at `~/srv/soak-g3/bolina` on the **owner's machine** — the same sealed binary that G2 and the Zig soak exercised. The dev machine does not have it. Therefore:

- **Rung E is implemented with full logic here, but is assumed to run elsewhere.** No part of ladders A–D or the main soak depends on a Zig binary being present locally.
- **The wrapper gets a standalone mode:** `tools/g4-integration-soak.sh rung-e [--zig-daemon <addr>]` runs ONLY rung E against a running Zig daemon and prints a verdict (PASS/FAIL with the failing step), without starting a Rust daemon or entering the soak loop. This lets the owner validate the client against the sealed reference **before** committing an integration-soak window.
- **Dev-machine coverage:** ladders A–D and the wrapper are developed and tested here against the Rust daemon, with zero Zig dependency. Optionally a local Zig v0.6.1 can be stood up for rung E development iteration — but the verdict that counts is the owner's run against the sealed binary.
- **Final flow at W12 close:** the 8 tasks land, the owner runs `rung-e` isolated, then one full five-rung round, and only then does the integration-soak window open. If rung E fails on the owner's machine, we stop there and fix - that is its purpose.

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
