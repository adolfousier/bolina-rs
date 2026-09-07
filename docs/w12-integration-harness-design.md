# W12 Integration Harness Design

**Status:** Design — awaiting owner review before implementation
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

| Step | Client Action | Expected Daemon Outcome |
|------|--------------|------------------------|
| 1 | Handshake + binding | Session established |
| 2 | Duplicate envelope (same hash as step 3 from ladder A) | insertEnvelope then idempotent OK (same hash) |
| 3 | Envelope with stale seq (seq=1 after window seeded at 1000) | checkSeq then WindowStale then rejected |
| 4 | Envelope with unknown parent hash | allParentsPresent then UnknownParents then rejected |
| 5 | Malformed envelope (truncated) | parse_envelope then Truncated then dropped |

**Expected counts:** 1 admission (duplicate, idempotent), 0 refusals, 3 rejections

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

A **round** is one complete execution of all four ladders:

```
round = ladder_A + ladder_B + ladder_C + ladder_D
```

Expected outcomes per round:

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

A round **passes** if all counts match expected values. Any deviation is a failure.

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
# Usage: g4-integration-soak.sh [--hours N] [--workers N] [--seed SEED]

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

## 8. Metrics Collection

Per-round metrics written to `integration-rounds.log`:

```
round=1 handshakes=4 bindings=4 admissions=6 refusals=1 rejections=3 http_202=2 http_422=1 http_400=1 sse=1 latency_ms=142 status=PASS
round=2 handshakes=4 bindings=4 admissions=6 refusals=1 rejections=3 http_202=2 http_422=1 http_400=1 sse=1 latency_ms=138 status=PASS
```

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
2. All four ladders pass in a single round
3. 100 consecutive rounds pass with 0 failures
4. The integration soak runs for >=1h with 0 failures

## 11. Implementation Order

1. **Client binary skeleton** — key generation, UDP socket, Noise_IK initiator
2. **Ladder A** — handshake + binding + intent + grant + effect
3. **Ladder B** — refusal path
4. **Ladder C** — admission rejection
5. **Ladder D** — control API
6. **Soak wrapper** — loop + metrics + reporting
7. **Daemon wiring** — each TODO, validated by the harness as it lands

The client and daemon wiring can proceed in parallel: the client sends correct packets from day one, and the daemon starts processing them as each TODO gets implemented.

## 12. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Daemon crashes mid-round | Soak wrapper restarts daemon, logs the failure |
| Session table exhaustion (MAX_SESSIONS=16) | Each round uses 4 sessions; rounds are sequential, not parallel |
| Ledger file growth | Soak wrapper uses TempDir, cleans up after |
| Port conflicts | Configurable ports, default 9800/9801 |
| Timing-dependent failures | Fixed delays between operations, configurable |

## 13. What This Does NOT Cover

- **Cross-node mesh** — this is single-daemon, single-client. Multi-node mesh routing (relay, served-cert) is out of scope for W12.
- **Performance benchmarking** — the soak measures correctness under sustained load, not throughput.
- **Zig interop** — this is Rust-daemon-only. Zig interop (G2-style) is a separate gate.

---

**Next step:** Owner review of this design. If approved, implementation starts with the client binary skeleton (section 11, step 1).
