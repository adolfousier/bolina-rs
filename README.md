# bolina-rs

Rust implementation head of the **Bolina protocol**: an intent/grant authority protocol where capabilities are signed, bound to cryptographic identities, auditable without clocks, and provable end to end. The reference implementation lives in Zig at [adolfousier/bolina](https://github.com/adolfousier/bolina) (tag `v0.6.1`).

## Why we are doing this

Bolina's Zig tree is mechanically done: 114+ SPEC properties under named tests, 176/176 non-equivalent mutants killed, 24h adversarial soak on real hardware, frozen conformance vectors passed byte-for-byte by an independent Go implementation (lastro), and a live cross-language handshake proven in the G2 gate. Nothing about this port is driven by a technical failure of Zig. It was a deliberate choice and it did its job.

So why Rust?

- **Community.** A reference language is also the community you build with. This house builds with AI agents, loops and automation; we want our ecosystem to want that too.
- **Adoption surface.** More people can read, audit and contribute Rust than any niche alternative. Protocol adoption beats language pride.
- **The method transfers.** Spec corpus, frozen byte vectors, mutation gates, signed receipts: none of it belongs to one language.

We are NOT rewriting history. The Zig tree stays supported as the live oracle until full parity and an explicit governance swap (decision D-096 in the parent repo). Everything already proven stays proven against frozen tags; this port extends the proof instead of inheriting it.

## Method (Huntley-style port)

- **Stage 2 (specs):** every Zig module compressed into `specs/<module>.md`, a contract sheet citing its tests by name and its source by file:line. No citations, no sheet; no sheet, no wave.
- **Stage 3 (waves):** implement against those sheets, wave by wave, with hard acceptance gates per wave.

| Wave | Scope | Acceptance gate |
|------|-------|-----------------|
| W0 | workspace, strict lints | cargo build/test green, empty tree |
| W1 | crypto head (audited crates) | RFC KATs: 7748 / 8032 / 8439 / 7693 green |
| W2 | codec Envelope/Intent/Grant/Refusal | frozen vectors.json byte-for-byte incl. negatives |
| W3 | intent table + durable grant ledger | ported test semantics + flock via seam |
| W4 | Noise_IK handshake + binding | LIVE interop vs the Zig daemon |
| W5 | relay/listener/session/daemon + HTTP control plane | pilot e2e |
| W6 | CA CLI + keys | cross-validation with the Zig verifier |

Crypto uses pinned, audited crates (ed25519-dalek family) as an explicit amendment to Bolina's zero-dependency rule (D-096-A): timing side channels are not provable by mechanical gates alone and we refuse to hand-roll crypto.

## Evidence-first

Every wave gate runs wrapped in a **Bolina receipt** signed by a CI identity: the protocol stamps its own port. Failures get receipts too (no selection bias). After parity: mutation testing domains, differential fuzzing Zig-vs-Rust with dual oracles, and a fresh 24h adversarial soak.

The full decision log lives in `LOGBOOK.md`, one line per decision: what, why, commit.

## Status

| Track | State |
|-------|-------|
| W0 workspace | done (`969a812`) |
| stage-2 corpus | 10/42 sheets |
| next | grant_ledger + dispatch sheets, then W1 KATs |

## Built by

Built by crabs first: engineered day and night by the [OpenCrabs](https://opencrabs.com) AI agent, directed by @loonix, growing with whoever shows up. Contributions welcome once the first wave lands: pick an unchecked sheet from `TODO.md`, keep specs honest, cite everything.

License: being finalized before v0.1.

---

Swap policy: NO reference swap until full parity (W6) plus the complete new evidence battery (cargo-mutants domains, Zig-vs-Rust cross-diff fuzz, re-soak signed with lastro).
