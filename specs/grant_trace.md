# grant_trace.zig - test-only conformance trace instrument (ZIG-TLA pilot)

## Status in the port: REPLACEMENT REQUIRED, not translation
This module is comptime-gated build-option instrumentation (opts.trace_enabled) backing model/ZIG-TLA-CONFORMANCE-BRIEF.md section 6. It exists to project runtime behaviour onto Bolina.tla actions. The Rust head needs the equivalent seam (feature flag + fixed ring) when its own TLA-conformance phase starts; until then it MUST NOT exist in production paths at all.

## Contract worth keeping whatever the mechanism
- schema "bolina.grant-trace.v1", CAP=256 fixed ring, zero heap zero I/O (grant_trace.zig:48-51)
- Event{tag:Tag(u8 18 variants + trace_overflow=255), pc:u8 (NO_PC=0xFF when absent), id:id64 fingerprint, id2 correlation slot or null, now_ms, seq:u32 monotonic} (grant_trace.zig:56-90)
- fingerprint = FNV-1a u64 over id bytes, offset basis 0xcbf29ce484222325 (pub fn fingerprint, ~line 106). Deterministic so recorded vs expected traces compare by value

## Load-bearing event-order rules (the two reasons this instrument exists)
- R1 commit_consumed_11 emitted ONLY after durable appendSync RETURNS OK. An event before the append would turn attempted durability into FALSE evidence (header comment, grant_trace.zig:8-10)
- R2 effect_start IS the normative APPROVED->EXECUTING transition (D-067); record_executing_witness is a later bookkeeping echo and must never be projected as authorization
- R3 effect_refused (D-078): refused path never emits mark_published or record_executing_witness afterwards; commit_consumed_11 row stands => durable UNPUBLISHED orphan (BE-GRANT-01a)
- R4 mark_published_failed (D-080 R1): fail-safe in control flow, loud in evidence; never projectable as MarkPublished success
- R5 prune_* events fire after EACH D-063 rewrite linearization point so crash-mid-prune shows last completed phase; expire_pending.pc carries collapse count

## Verification heritage
No unit tests in-file BY DESIGN: correctness lives in the ZIG-TLA conformance pilot harness comparing emitted traces against TLA+ action sequences. Rust equivalent inherits the same acceptance criterion: projected traces must satisfy the Bolina.tla invariants, including the two-load-bearing rules above.

## Rust disposition
Defer implementation until TLA phase; implement as #[cfg(feature="tla-trace")] ring with identical Tag numbering (wire-stable ids keep recorded traces comparable across implementations). Do NOT let it silently become always-on.
