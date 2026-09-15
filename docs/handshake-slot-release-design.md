# Handshake slot release: decoupling design (2026-09-15)

**Status:** Proposal, awaiting Daniel + owner decision. src/ change → next
candidate (post-seal, §15). Nothing here is wired; the guard landed 2026-09-14
(64bb27b) is what keeps the wall loud until this lands.

## 1. Problem (measured, not inferred)

`handshake::Table` commits 16 slots (`MAX_SESSIONS = 16`, handshake.rs:20)
and **nothing on the daemon path ever releases them**. Measured 2026-09-13
(16 rounds × 300 envelopes, `.g5-load/`): rounds 0-3 pass, round 4 onward
every wire ladder dies at `msg2` with `bind/trp/prs = 0` and `hadm + 1` alive.
4 wire handshakes/round (A, B, C, V; D is control-plane) × 4 rounds = 16,
the table arithmetic exactly. Ledger peaked ~1 220 live and could not reach
the 4 096 cap in soak. This was defect #8 of the series; the `handshake_full`
reject class (bbca81e) made it countable, the wrapper guard made running past
it a declared choice.

`release_slot` and `release_stale` already exist (handshake.rs:79, :95) with
three unit tests - they are simply not called from the daemon, because of §2.

## 2. The coupling (why the naive fix is forbidden)

On admit (daemon.rs:263-275), the **handshake slot index is reused as the
transport `local_index`**: `sessions.admit(slot as u32, 0, ...)` and
`peer_static[slot]`. The transport header's `receiver_idx` on the wire IS
that number. So:

- Reallocating session indices (the clean decoupling) changes which number
  msg2 hands the client and which number the client sends back - a **wire
  divergence from the Zig reference**, which allocates the same way. That
  kills rung E byte-interop, the one mechanism we froze the reference to
  preserve. Rejected on principle, not convenience.
- The tables therefore must keep sharing the index space. What can be
  decoupled without touching a single wire byte is the **lifetime**.

## 3. Options

| Option | Mechanism | Verdict |
|--------|-----------|---------|
| A. Release on transport close | UDP/Noise session end signal | Does not exist - there is no close signal in the frame format |
| B. Idle-timeout release, synced | `release_stale` on tick + mirror cleanup | **Recommended** (§4) |
| C. Separate index spaces | msg2 remap | Wire divergence from reference. Rejected (§2) |
| D. Restart per epoch (today) | daemon restart every 4 rounds | The status quo the guard documents; not a fix, a tourniquet |

## 4. Design (option B)

One constant: `T_HS_IDLE_MS = 900_000`, deliberately equal to the system's
own staleness horizon `T_PENDING_MS` (Zig intent.zig BE-GRANT-06). A session
silent longer than the horizon the system already uses to decide a lane is
stuck is, by the system's own clock, dead. Inheriting an existing constant's
value keeps the lifetime claim reviewable against a documented number
instead of a new magic one.

Per drain pass (daemon.rs loop, alongside `poll_control`):

1. `hs.release_stale(now_ms(), T_HS_IDLE_MS)` returns freed indices;
2. for each freed index: `sessions.release(idx)` and
   `peer_static[idx] = None` - the three structures share one index space,
   so the release MUST be a single `fn release_hs_slot(&mut self, idx)`
   touching all three, never three call sites;
3. new counter `handshake_released_total` bumps by the count;
4. new gauge `handshake_slots_used` already exists as
   `Daemon::handshake_slots_used()` (daemon.rs:136) - expose it in
   `metrics_body`. Wall, releases and occupancy become all readable in one
   scrape: `handshake_full` says you hit it, `released_total` says the
   table is recycling, `slots_used` says how full it is right now.

`TableFull` keeps its current meaning for genuinely *live* occupancy (>16
concurrent silent-less executors): the wall becomes physical, not clerical.

### Safety argument (slot steal)

A slot released at idle-T, then taken by a fresh handshake, holds new keys.
The old peer's next packet fails `sessions` decrypt/counter checks and is
counted in the `transport` class - it cannot decrypt under the new session's
keys, so no cross-session confusion is possible even adversarially; the old
peer's only recovery is re-handshake, which the client does per ladder
anyway. The observable cost of a wrong T is a counted transport reject,
bounded and visible; the cost today is a terminal wall.

### Zig parity

Slot *lifetime* is not a wire-observable protocol property; rung E compares
bytes, and none change. But the reference never releases, so a long un-
epoched soak now behaves differently between the two daemons (Rust survives
round 5, Zig dies at 4). Same precedent as the drain fix (pending #2): the
soak contract is the port's, and the port leading the frozen reference here
is allowed - stated here so the next interop run that sees an asymmetry
reads it as policy, not defect.

## 5. Measurement plan (what makes it verifiable, per §15 discipline)

| Gate | Check |
|------|-------|
| Unit, table | fake-clock: 16 commits → 17th `TableFull` AND `handshake_full+1`; advance past T, `release_stale` frees exactly the expired; 17th now commits; `released_total` moves |
| Unit, daemon sync | after a release, `sessions.lookup(idx)` misses AND `peer_static[idx]` is None - the three-structure invariant, tested as one unit because the bug shape is partial release |
| Metrics | `handshake_slots_used` + `handshake_released_total` lines pinned in `metrics_body` tests (w10/w13 pattern) |
| Soak acceptance | `--epoch-rounds 20` on target WITHOUT `--allow-handshake-cap`: all 16 rounds pass, `hf+0` every round, and the ledger passes ~1 220 and walks toward 4 096 - the live measurement that §2 of pending-corrections could only answer deterministically (w14 stays as the pin; this makes cap-arrival observable, not just affordable) |

If the soak acceptance trips `ledger_arrivals < floor` with `bind+0` and
`hf+0`, that is a NEW finding under the same tripwire - the floor stays
untouched regardless of what it finds.

## 6. Decision requested

Landing slot = **next candidate, after the seal** (my opinion, stated as
biased: the guard already removed the silent-wall danger, the 8 h §16 soak
runs 4-round epochs by design and does not need release, and the one live
measurement this unlocks - ledger walking to 4 096 - is confirmation of a
number w14 already pins, so nothing that decides the seal waits on it).
The opposite call - release before seal because §2's hole is "the only one
that worries me" territory - is defensible; it costs one more candidate
cycle and re-runs §16. Either way the design above is the work; it just
needs a slot.
