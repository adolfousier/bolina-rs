# evidence.zig contract sheet (src/evidence.zig, 294 lines)

## Contract
Claim resolution per SPEC 7.2/7.3 (Utterance layer). PURE functions: map a
method_id to an evidence class + integer ceiling, then resolve one claim
against inline spans -> three-state verdict. Integers only; floats are
FORBIDDEN in this module's logic (normative comment :59-63, BE-EVID-15).

## Public surface (cites)
- EvidenceClass enum (:48): direct_observation / expert_testimony /
  documentation / inference.
- classOf(method_id) :55-68: 1..4=direct_observation, 5..6=documentation,
  7=expert_testimony, 8=inference, **else=inference** — unknown method_id
  DEGRADES to the weakest class, never an error (BE-EVID-13 :66).
- ceilingQ8(class) :71: normative integers only: 242 / 216 / 191 / 165.
  Comment pins why: 0.95*255=242.25 and ROUNDING UP would exceed the declared
  cap by one LSB. Rust must keep u8 integers; any float conversion is a
  review-blocking defect.
- isVolatile(volatility) :87: unrecognized volatility byte IS volatile
  (fail-closed, BE-EVID-06).
- effectiveConfidence(stated_q8, strongest_ceiling_q8) :102: min() semantics,
  receiver recomputes; no matching span = ZERO not floor (BE-EVID_02a);
  unresolved origin = INDETERMINATE not zero (BE-EVID_02b).
- checkBounds(claim_count, span_count) :116 with MAX_UTTERANCE_CLAIMS=32,
  MAX_UTTERANCE_SPANS=64 (:113-114).
- resolveClaim(...) :236: walks claim.span_ids, matchSpan against inline
  spans; cited-but-not-inline counts as CITED but supports nothing
  (BE-EVID_08 :250 `continue`). Result union ClaimState (:188):
  supported / unresolved / unsupported — exactly three states (BE-EVID_09).
- Role/OriginState/ResolveContext/ResolutionRecord/Supported structs
  (:139-186).

## Rust mapping notes
- Pure fn module; no I/O, no clocks. All inputs carried by ResolveContext.
- ClaimState as exhaustive Rust enum; match arms total.
- The ceiling table is NORMATIVE DATA: encode as const [4]u8 indexed by class;
  a mutant that bumps any cell must die (named test below covers 242 path).

## Tests inherited (name-mandatory in Rust), src/evidence_test.zig
- :24 span supports ONLY with verifying sig + executor role (BE_EVID_01)
- :66 receiver recomputes min(stated, strongest ceiling) (BE_EVID_02)
- :99 no matching span => zero, not floor (BE_EVID_02a)
- :130 unresolved origin => indeterminate, not zero (BE_EVID_02b)
- :149 span supports only when resource == subject (BE_EVID_03)
- :181 confidence arithmetic deterministic (BE_EVID_04)
- :196 superseded volatile span stops supporting (BE_EVID_05)
- :224 unrecognized volatility byte is volatile (BE_EVID_06)
- :251 stable span never superseded (BE_EVID_07)
- :273 referenced-not-inline span supports nothing (BE_EVID_08)
- :293 three states supported/unresolved/unsupported (BE_EVID_09)
Consumers: dag_test.zig, evidence_record_test.zig (record side, separate
sheet for record.zig if split later). Hooks exist for utterance wiring but
wiring itself stays deferred (RED-TEAM-09 F1 decision) — do NOT build
production call-sites beyond this pure layer.
