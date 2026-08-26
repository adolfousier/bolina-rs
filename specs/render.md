# stage-2 contract sheet 01/42 — `render.zig`

Source: `src/render.zig` (56 lines). Tests: `src/render_test.zig` (4 named).
Wave target: **W2** (codec-adjacent pure layer).

## Contract

View-layer for the approval UI (SPEC.md 8.3, BE-GRANT-07/07a). Pure function
over parsed values; fixed shape; no allocation (`render.zig:14`). Excluded
from M11 line budget via the BE-SURF-03 non-surface list placed ahead of
creation by D-052 (`render.zig:15-17` tripwire note).

## Public items

| Item | Shape | Rust mapping |
|---|---|---|
| `RATIONALE_UNTRUSTED_LABEL` | `[]const u8` = "untrusted, agent-authored" | `pub const RATIONALE_UNTRUSTED_LABEL: &str` |
| `Rationale` | `{ text: []const u8, untrusted_label = LABEL }` | struct with `Default` carrying the label |
| `ApprovalView` | 4 fields, order IS render order | struct; field order documented as render order |
| `renderApproval(canonical_resource_id, action, rationale) -> ApprovalView` | infallible | free fn `render_approval` |

Error set: empty (total function).

## Invariants (each must be preserved or violated loudly)

1. `render_approval` takes exactly THREE parameters and NO digest parameter;
   a wire digest has no path into the view
   (`render.zig:41-46`; test `"BE_GRANT_07 no wire digest enters the view"` at render_test.zig:45).
   Rust: same 3-param signature; any refactor adding a digest param must fail review.
2. The view digest is RECOMPUTED from the action bytes carried in the view,
   through the same primitive the Grant binding uses:
   `verify.actionDigest(action)` (`verify.zig:114`),
   digest length `LEN_ACTION_DIGEST = 32` = BLAKE2s-256 of Intent.action
   (`parser/channel.zig:39`, BE-GRANT-02)
   (`render.zig:47-49`; test at render_test.zig:27 asserts equality with the recomputed digest).
3. Displayed rationale is marked untrusted BY THE TYPE: default field value,
   there is no path that displays rationale without the label
   (`render.zig:20-33`; test at render_test.zig:59).
4. Field order IS render order: primary content first, non-optional, rationale
   last and optional; `None` means not displayed at all - rationale can never
   be the sole visible element
   (`render.zig:34-42`; test at render_test.zig:89).
5. Action bytes are rendered in full, never a summary
   (`render.zig:35`; test at render_test.zig:27).

## Test semantics checklist (port these as named tests)

- [ ] view carries canonical id + full action + digest equal to `action_digest(action)` (render_test.zig:27)
- [ ] no wire digest can enter (signature-level check) (render_test.zig:45)
- [ ] Some(rationale) => labeled untrusted, subordinate position (render_test.zig:59)
- [ ] None(rationale) => field absent entirely, never empty display (render_test.zig:89)

Rust target: `bolina-rs/src/render.rs`, same module boundary, `#[must_use]`,
no allocation. Gate: tests above ported with names intact; clippy clean.
