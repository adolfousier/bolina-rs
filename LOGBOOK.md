# LOGBOOK

Ship's log of the Zig -> Rust port. One line per decision: what, why.
Signal only. Full context lives in the linked decision entries.

## Format

`YYYY-MM-DD | sha | what | why (one clause)`

## Entries

2026-08-26 | d24cf74 | D-096 filed: Zig->Rust port approved, crypto via audited crates (BE-DEP-01 amendment A), G1 launches in parallel against frozen tag v0.6.1 | owner decision; ecosystem friction is first-class engineering
2026-08-26 | 969a812 | W0 scaffold: strict lints (deny warnings, forbid unsafe), toolchain pinned 1.98.0, ReleaseSafe-parity profile, six wave stubs; gate green | Huntley stage-3 needs a new repo while the Zig tree stays reference + oracle
2026-08-26 | (this commit) | New repo separate from bolina, not same repo | stage-3 consumes specs from here citing Zig sources over there; two live trees required for cross-diff oracle later
2026-08-26 | (this commit) | Disk cleanup: removed 44GB .zig-cache from bolina (mutation-run build artifacts, fully regenerable); zig-out/logs untouched | cache was 63% of repo weight; requested hygiene, zero evidence impact (regenerable by design)
