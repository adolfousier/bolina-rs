# historical.zig contract sheet (src/historical.zig, 105 lines)

## Contract
NO-CLOCK audit path over accepted envelopes. The TYPE SYSTEM is the proof:
validateCertNoClock returns CertChainError, a set that cannot name CertExpired,
so no hidden clock check can compile into this path (D-089 disclosure; pack
§platform cites it). Validate roles, quorum, BE-REV-01 lifetime cap (property
of cert BYTES not of now), CA signatures, trust set - all without "now".

## Public surface (cites)
- historicalValidity(envelope, ctx) CertChainError!void over parseCert output.
- AuditContext carries trust set + anchors (ledger.getAnchor consumers).
- Split lives in binding.zig: validateCert (with window, admission path) vs
  validateCertNoClock (audit path) - KEEP THE SPLIT VERBATIM in Rust
  (binding.md sheet has the signatures).

## Invariants
- BE-HIST-01 audit validates the chain structurally; fixture certs are REAL
  (cert_test_helpers.buildCertInto), not undefined literals
  (ledger_test.zig:18-20 comment).
- BE-HIST-04 causal: envelope BEFORE its revocation hash audits OK via
  ledger.getRevokeHash + DAG ancestry (isAncestorIdx strict: false on a==b).
- BE-HIST-04a ACCEPTED LIMITATION (BRIEF §7.2): audit revalidates against the
  CURRENT trust set; rotated-out CA fails historical envelopes (UntrustedCA).
  Document, do not fix.

## Tests inherited (name-mandatory in Rust)
- rogue-CA through historicalValidity must fail UntrustedCA (commit b047043)
- expired-cert-at-audit still passes chain checks when inside its own bytes'
  window-bytes vs anchors; the CLOCKLESS property is asserted by TYPE (no
  now_ms parameter exists to pass)
- revocation causality pair from ledger_test.zig:192-212 reused here end-to-end
