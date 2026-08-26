# Contract sheet: token.zig

Source of truth: `~/srv/zig/bolina/src/token.zig` (78 lines).
Tests ported from: `token_test.zig` (90 lines).

## What it is

Control-plane bearer token (D-091 §3, F7 ruling): 32 random bytes, hex on
disk and in the header, 0600 file, timing-safe compare. Loopback-only plane;
the token defends against same-user processes and drive-by localhost pages
(`token.zig:2-7`).

## Public surface

- `TOKEN_BYTES = 32`, `TOKEN_HEX_LEN = 64` (`token.zig:16-17`)
- `TokenError = { DiskError }` (`token.zig:19`)
- `generate(io) -> [32]u8` - CSPRNG, same entropy source as key material
  (`token.zig:26-30`)
- `hex(token) -> [64]u8` - lowercase fixed-width (`token.zig:33-40`)
- `save(io, data_dir, hex)` -> DiskError; createFile 0600, truncate allowed,
  NOT exclusive by design: overwrite is deliberate rotation
  (`token.zig:43-52`, comment 43-44)
- `load(io, data_dir) -> ?[64]u8` - null on absent/short/corrupt; NEVER a
  fallback token (`token.zig:54-67`)
- `verify(provided, expected) -> bool` (`token.zig:68-78`)

## Invariants

1. **Fail-closed**: `load() == null` means "auth impossible", not "auth
   skipped" - every request except /healthz refuses (`token.zig:8-10`).
2. **No silent rotation**: regeneration only via explicit operator delete;
   a restart must not rotate credentials under running clients
   (`token.zig:9-10`).
3. **Constant-time compare with length pre-check** (`token.zig:70-77`):
   length mismatch exits BEFORE comparing (length may leak; content never);
   provided input is copied into a stack buffer first so the constant-time
   primitive gets equal-length arrays without branching.
4. **Filename fixed** as `control.token` inside data_dir (not configurable;
   `token.zig:18`).

## Test checklist -> Rust asserts

| Zig test | line | Rust assert |
|---|---|---|
| two draws differ, hex is 64 lowercase chars | `token_test.zig:32` | generate() twice differ; hex matches `^[0-9a-f]{64}$` |
| save/load roundtrip through a real dir | `token_test.zig:45` | save then load returns the same hex |
| load fail-closed: absent dir null, truncated on-disk token null | `token_test.zig:57` | missing dir -> None; 63-byte file -> None |
| verify: exact match true; flip, wrong length, wrong case all false | `token_test.zig:76` | equal ok; one byte flipped false; len !=64 false; UPPERCASE form false |

## Rust-side notes

- Lives in W5 (control plane). Trivial once W0 exists; can be sheeted into
  code early since it has no crypto-head dependency beyond CSPRNG
  (`rand::rngs::OsRng` or getrandom).
- 0600 permissions: use `std::os::unix::fs::OpenOptionsExt::mode(0o600)`
  at creation; Windows parity is explicitly out of scope for this layer.
