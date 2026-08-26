# bolina-rs

Rust reference candidate for the Bolina protocol. Huntley-method port from the Zig head.

- Plan + edge scenarios: `~/.opencrabs/projects/bolina/rust-port-huntley-plan.md`
- Zig baseline: `1b88522` · Crypto fork: D-096-A (audited crates pinned) · Waves W0-W6
- Swap policy: NO reference swap until full parity (W6) plus complete new evidence battery
  (cargo-mutants domains, Zig-vs-Rust cross-diff fuzz, re-soak signed with lastro)
