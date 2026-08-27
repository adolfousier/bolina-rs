# ca_cli.zig -> cli/ca (W6)

Source: `src/ca_cli.zig` (187 lines). Material logic lives in ca_material (see specs/ca_material.md) - the CLI is the ARGV SHELL over it.

## Contract

`maybeRun(io, args: []const [:0]const u8) !bool` (ca_cli.zig:92): called from main BEFORE daemon boot; returns false = "not a CLI invocation, boot the daemon". Flag-driven, NOT positional subcommand+flags mix.

## Error set (exact, 6 variants)

CliError (ca_cli.zig:21-29): `UnknownCommand`, `MissingFlagValue`, `BadTtl`, `BadScopeHex`, `ScopeOverrun`, `SerialNotFound`. Rust enum identical; no anyhow-style lumping (D-049 analog).

## Flags surface

Flags struct (L30). observed at runtime: `--dir` (work root), `--ca-dir`, `--node-dir`, `--out`, `--role`, `--ttl`, `--scope` (RAW HEX bytes, 16 hex chars per scope, buffer [8][8]u8 - ca_material ZULU; canonical `bol:` form is REJECTED here by design), `--serial`.
Caps: MAX_SERIALS_LIST=128 (:19), MAX_PATH=512 (:18).

## Commands

init / issue / list / show / revoke (wired in main.zig dispatch). Note recorded on the trail: revoke's `--out` requires parent dir to exist - wart kept visible, not silently mkdir'ed.

## Required Rust tests (named identically from ca_cli_test.zig)

- "P3 init writes root keys and anchors the daemon loads" (:66)
- "P3 issue produces a cert the daemon accepts end to end" (:84) - THE acceptance: cross-validates against Zig parseCert
- "P3 tampered tbs dies at the CA signature check" (:114)
- "P3 approver issuance enforces quorum and span cap" (:138) - BE-ID-03 + BE-REV-01 at issuance
- "P3 revoke emits a BE-CTRL-03 body the verifier site parses" (:187)

## Heritage notes

- v3-always issuance is enforced in ca_material (F15 kill-test named there); the CLI layer must keep printing the empty-scopes deny-all notice.
- TTL validation rejects non-integer AND >30d span (BE-REV-01); rejection text names the RFC-decision.
