# sheet: historical.zig (audit validity, clock-free) — W3

Source: bolina/src/historical.zig (105 lines). Tests: src/ledger_test.zig.

## Contract
Historical validity of a COMMITTED envelope, judged as of commit time. No wall clock ever touches this path: a committed signature stays valid after its cert expires; only a structurally unsound chain is invalid at ALL times. Admission-time revocation is immediate (`ledger.isRevoked`); audit-time revocation is CAUSAL (DAG ancestry).

## Public API
- `HistoricalError = error{ AnchorNotFound, NotDescendantOfAnchor, DescendantOfRevocation, UntrustedCA, ...chain errors }` — historical.zig:23
- `AuditContext { ledger: *Ledger, dag: *Dag, sender_cert: Cert, trusted_ca_keys }` — :46
- `historicalValidity(env_hash [32]u8, sender [32]u8, ctx) HistoricalError!void` — :65
- `validateCertNoClock(cert, trusted_ca_keys)` — :103 → delegates to binding.validateCertNoClock (the chain split lives next to the clocked validateCert it mirrors)

## Invariants (each with kill-proof obligation in Rust)
1. **BE-HIST-01 zero clock**: the error set CANNOT name CertExpired; the type system proves no temporal check hides here. Chain, roles (BE-ID-02..04), quorum, BE-REV-01 span cap and CA signatures are all still enforced — historical.zig:96-100.
2. **BE-HIST-03 anchor ancestry**: envelope must be DAG-descendant of the sender's anchor; missing anchor = `AnchorNotFound` (:76), non-descendant = `NotDescendantOfAnchor` (:77-79).
3. **BE-HIST-04 causal revocation**: violation exists ONLY when env_hash is descendant of the recorded revoke hash (:86-90). Pre-revoke envelopes stay historically valid (that's the point).
4. **Caveat BE-HIST-04a (accepted trade)**: CA trust set is the CURRENT one; rotated-out keys break old audits. Documented, accepted-with-name.

## Test checklist (port as named tests)
- "BE_HIST_01 audit path runs the chain but not the clock" / "still enforces the chain without a clock" — ledger_test.zig:556/577
- "BE_HIST_01 historicalValidity enforces the chain on the sender cert" (+ rogue CA → UntrustedCA at :537) — :508
- "BE_HIST_03 descendant of anchor passes" / "not descendant fails" / "descendant of revocation fails" — ledger_test.zig:392/417/439
- "BE_HIST_04 envelope committed BEFORE the revoke stays historically valid" — ledger_test.zig:476
