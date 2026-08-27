# ca_material.zig — CA issuance contract (offline CLI core)

Source: `src/ca_material.zig` (297 lines) · refs f:line. Tooling layer: NO wire frames; produces certs consumed by binding.validateCert* on both Zig and (post-W6) Rust verifiers.

## Public surface
- DOMAIN_CERT=0x01 over cert.tbs BE-SIG-01 (ca_material.zig:25)
- Closed Error set :30 (D-049)
- joinPath bounded (:43) · serialOf(tbs)[32] = BLAKE2s-256 hash, first 16 bytes used as serial (:67)
- caInit(dir,count) two roots layout (:96) — anchor files ca0.pub/ca1.pub + private halves 0600
- roleFromString: agent|executor|approver only (:119-122)
- IssueReq{:126} / IssueResult{serial_hex}(:135)
- caIssue(req) (:174):
  - **emits cert version = 3 ALWAYS** (F15 fix, commit 9c96732 heritage): v3-with-empty-scopes = deny-all D-085 R4; the old "v2 when scopes empty" trap is BANNED with a named Rust test.
  - privileged role span cap enforced at issuance vs BE_REV_01 30d (:181 pairing check approver/executor => <= MAX_PRIVILEGED_LIFETIME_MS)
  - dual CA signatures for approver quorum written into sig slots
- issuedPath(ca_dir,serial) layout (:268) · caRevoke(dir, serial, subject_expiry_ms?, out) (:282) — **BE-CTRL-03: body carries SUBJECT expiry** (never admin's); absent body = prune never.

## Invariants / test names to port
1. Roundtrip: issue => parseCert ok => validateCert passes with the issuing anchors (clock-free variant too).
2. Version byte pinned == 3 for every issue path (the F15 killer test).
3. Over-long TTL request refused at CLI level (BE_ID-03-family refusal, not silent clamp).
4. Serial = blake2s(tbs)[0..16] lowercase hex; recomputable.
5. Revoke envelope bytes replayable against verify.zig setRevocation path incl. subject-expiry consumption (verify.zig:708 heritage).

## Heritage
caIssue output is consumed DIRECTLY by W6 acceptance cross-checks against the Zig verifier and by lastro keygen layouts (sig.pub/static.pub naming was proven interop-compatible with bolina ca issue).
