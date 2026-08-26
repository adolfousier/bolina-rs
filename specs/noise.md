# noise.zig -> noise stage-2 sheet (10/42)

Source: src/noise.zig (460 lines). Tests: src/noise_test.zig (235 lines, 10 named BE_TR_04/01).
Role: Noise_IK state machine - the ONLY handshake crypto. W4 gate = live interop vs Zig daemon
(no frozen vectors exist for the handshake by design: the live exchange IS the oracle).

## Contract
Pure state machine over fixed-size byte buffers. Zero allocation, zero clock, zero syscalls.
Two roles: Initiator (244) / Responder (356), both yielding HandshakeResult with c1/c2
transport keys (87). All sizes compile-time consts (42-74).

## Public API (must match 1:1 in Rust signatures unless noted)
- consts: DHLEN=32 HASHLEN=32 KEYLEN=32 TAGLEN=16 NONCELEN=12 (:42-46)
- PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_BLAKE2s" (:50)
- MSG1_SIZE=144, MSG2_SIZE=92, BEFORE_MAC1 offsets (:55-58)
- Error set EXACTLY {Mac1Failed, DecryptFailed, IdentityPoint} (:79) [D-049 analog]
- transportNonce(counter u64) -> 12B (:105)
- SymmetricState: init/mixHash/mixKey/encryptAndHash/decryptAndHash/split (:134-213)
- keypairFromSecret (:230); Initiator{init,writeInitiation,readResponse,finalize} (:244-347);
  Responder{init,readInitiation,writeResponse,finalize} (:356-456)

## Invariants (each becomes a Rust test)
1. Nonce = 4x00 || BE counter [BE-TR-04] (noise_test:14)
2. mac1 check precedes ANY X25519 math, incl degenerate ephemeral (tests :165/:187/:210 -
   three separate rejection sites: responder msg1, initiator msg2, forced-identity case)
3. Tampered ct must fail decrypt (test :106) - AEAD tag enforced everywhere
4. Round trip derives MATCHING c1/c2 (test :146) - W4 live proof extends this cross-language
5. Byte layout of responses: sender_index@4, receiver_index@8 (consts :69-70).
   G2 HISTORY: call site passed these swapped until e4fd0d4; Rust MUST carry the byte-level
   kill-proof test (pin daemon slot + initiator echo) per specs/handshake.md inheritance rule
6. SymmetricState seeded from PROTOCOL_NAME hash with no key (test :30)

## Test port checklist (from noise_test.zig, all become #[test])
10 tests: nonce shape, ss seeding, mix determinism, split fixed pair, enc/dec inverse,
tamper-reject, IK round-trip transport keys, 3x mac1-before-X25519 ordering.
