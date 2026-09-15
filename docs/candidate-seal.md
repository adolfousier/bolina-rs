# Candidate seal — drain+pacing series (2026-09-15)

Seal authority: Daniel (@iamloonix). The repository owner (Adolfo) gates
only the GitHub-visible moves: the tag `frozen-reference-2026-09-14`
reaching adolfousier/bolina and the reference swap in the Zig tree. No
push, tag or swap happens without his explicit OK. There is no
"owner approves the seal" blocker; that decision does not exist.

Candidate identity: `main` as of the commit that lands this file. Verify
with `git ls-remote origin refs/heads/main`; the last non-documentation
commit beneath the seal is `33b345c`.

## What this seal covers (measured, with receipts)

- G3 soak: 4 h 30, co-tenancy sampled 288/288 clean, one unreproduced
  anomaly round (docs/g3-soak-receipt.md).
- G4 re-run: 18 280/18 280 rounds on the owner's box with admission
  **proved** by the wire counters (`b859732`, `81c0228`); the ladder-A
  u16be defect found, attributed and corrected in the same receipt.
- G5 / VOL-1: 11 944/11 944 rounds, 23.89 M envelopes sent (10–11 Sep
  window), plus the attribution re-run on the owner's machine: A2 4/4
  PASS paced (`ledger_inserts +300`), B2 2/2 FAIL unpaced
  (docs/g5-volume-soak-receipt.md). The G5 re-issue with *measured*
  admission follows as a 1 h instrumented re-run; per the G4 receipt's
  own follow-on note it does not block this seal.
- Ledger cost at cap, both terms: `w14_ledger_sizing` times insert-dedup
  and the dominant parent-check at 4 096, with the absent-parent ratio
  control proving the scan order, not the machine. Worst case ≈ 54 µs vs
  the 100 µs/envelope pacing budget — margin ~2×, verify and fsync NOT
  included, and no margin claim survives without those terms.
- Kit pause/restore proven on the owner's machine, happy AND adversarial
  path; the restart pin is verified by read-back of the effective value.
- Suite 384/0/0, client 4/4, `cargo fmt --check` clean.

## What this seal does NOT cover (flat, same altitude each)

- 62/62 mutation kills are a hand-written regression net, not coverage:
  zero wire-framing mutants, verify has 3, handshake 1. The u16be class —
  the one wire defect this project really had — has zero mutants. The
  handshake-cap class is covered by the soak + wrapper guard, not by the
  mutation set.
- The daemon never releases a handshake-table slot on the production
  path. A process accepts 16 handshakes total (`handshake.rs:20`,
  `MAX_SESSIONS = 16`); after that, every further wire handshake is
  counted as `handshake_full` and that wire path is dead for the
  lifetime of the process. The `--epoch-rounds` guard against running
  into the wall lives in the soak wrapper only, not in the daemon; a
  consumer of this candidate that opens more than 16 handshakes over a
  process lifetime gets a counted, terminal wall. Slot release is the
  FIRST work item of the next candidate
  (docs/handshake-slot-release-design.md, decision 2026-09-15).
- Live ledger behaviour approaching the 4 096 cap end-to-end is not soak
  measured: no run passed ~1 220 live envelopes because the 16-slot wall
  arrives first. The cap cost is answered deterministically (w14), not
  in-situ; the in-situ confirmation arrives with slot release, post-seal.
- Every latency number in this series comes from the owner's co-tenant
  local machine (hostname `mengle`, reached by ssh alias `orbit-ext`,
  192.168.1.101, user `loonix`; the `ssh mengle` alias is a different
  machine, production Hetzner; bot, opencrabs, gitlab-runner and cron
  sampled every 300 s by `g5rerun.sh`). None comes from an isolated lab
  box. The latencies are co-tenant numbers — that is what gives them
  value, not what limits it.

## Handover

- Pending #2 (handshake slot release) transfers to the next candidate as
  its first item, design closed as input.
- Pending #1's remaining step: the 1 h instrumented volume re-run for the
  G5 re-issue.
- Zig reference tree frozen, not archived (owner decision, `14b605c`);
  the tag `frozen-reference-2026-09-14` exists on the reference checkout
  and its GitHub visibility awaits the repo owner.
