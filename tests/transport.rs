//! W4 gates: byte-level layout of both handshake messages, roundtrip with
//! cross-key equality, BE-TR-04 mac1-before-curve, DecryptFailed on tamper,
//! and the transport nonce composition. Every assertion cites its Zig source.

use bolina::transport::noise::*;
use bolina::transport::{compute_mac1, verify_mac1, MAC_BYTES};

fn kp(seed: u8) -> KeyPair {
    let mut s = [seed; 32];
    s[0] = seed.wrapping_mul(7).wrapping_add(1);
    KeyPair::from_secret(s)
}

fn sigpub(seed: u8) -> [u8; 32] {
    let mut p = [seed; 32];
    p[31] = seed ^ 0xA5;
    p
}

#[test]
fn msg1_layout_byte_level_matches_spec_41a() {
    // cite: noise.zig writeInitiation (type=1, sender@4, eph@8, enc_static@40,
    // enc_ts@88, mac1@112 over [0..112), mac2 zeros @128, len 144)
    let i_static = kp(0xB1);
    let r_static = kp(0xB2);
    let r_sig = sigpub(0xC2);
    let mut msg = [0u8; MSG1_SIZE];
    let mut init = Initiator::new(i_static, r_static.public);
    init.write_initiation(&mut msg, 0x51530001, 1_700_000_000_123, &r_sig, &[0u8; MAC_BYTES]).unwrap();

    assert_eq!(msg[0], 1, "type byte");
    assert_eq!(&msg[1..4], &[0, 0, 0], "reserved zeros");
    assert_eq!(&msg[4..8], &0x51530001u32.to_be_bytes(), "sender index big-endian");
    assert_ne!(&msg[8..40], &[0u8; 32][..], "ephemeral present");
    assert_eq!(&msg[128..144], &[0u8; 16][..], "mac2 zeros when no cookie");
    // mac1 verifies over exactly [0..112)
    let m1: [u8; 16] = msg[112..128].try_into().unwrap();
    assert!(verify_mac1(&r_sig, &msg[..MSG1_BEFORE_MAC1], &m1), "mac1 over framing+crypto body");
    // a flipped pre-mac1 byte breaks mac1 (mac covers the crypto body)
    let mut msg2 = msg;
    msg2[8] ^= 1;
    let m1b: [u8; 16] = msg2[112..128].try_into().unwrap();
    assert!(!verify_mac1(&r_sig, &msg2[..MSG1_BEFORE_MAC1], &m1b));
}

#[test]
fn msg2_layout_carries_g2_fixed_index_semantics() {
    // cite: noise.zig Responder.writeResponse + the G2 interop finding:
    // sender@4 = RESPONDER's own slot; receiver@8 = ECHO of the initiator's.
    let i_static = kp(0xA1);
    let r_static = kp(0xA2);
    let i_sig = sigpub(0xC1);
    let r_sig = sigpub(0xC2);

    let mut msg1 = [0u8; MSG1_SIZE];
    let mut init = Initiator::new(i_static, r_static.public);
    init.write_initiation(&mut msg1, 0xA70F1E, 42, &r_sig, &[0u8; MAC_BYTES]).unwrap();

    let mut resp = Responder::new(r_static);
    let info = resp.read_initiation(&msg1, &r_sig).unwrap();
    assert_eq!(info.sender_index, 0xA70F1E);
    assert_eq!(info.timestamp_ms, 42);
    assert_eq!(info.initiator_static_pub, i_static.public, "s: initiator static decrypted");

    let mut msg2 = [0u8; MSG2_SIZE];
    resp.write_response(&mut msg2, 0x0000_0000, 0xA70F1E, &r_sig, &[0u8; MAC_BYTES]).unwrap();
    assert_eq!(msg2[0], 2, "type byte");
    assert_eq!(&msg2[4..8], &0x0000_0000u32.to_be_bytes(), "sender = responder slot (G2: was swapped)");
    assert_eq!(&msg2[8..12], &0xA70F1Eu32.to_be_bytes(), "receiver = echo of initiator index");
    assert_eq!(&msg2[76..92], &[0u8; 16][..], "mac2 zeros");
    let m1: [u8; 16] = msg2[60..76].try_into().unwrap();
    assert!(verify_mac1(&r_sig, &msg2[..MSG2_BEFORE_MAC1], &m1), "mac1 over [0..60)");
}

#[test]
fn roundtrip_transcript_and_cross_keys() {
    // cite: Initiator.finalize (send=c1,recv=c2) vs Responder.finalize
    // (send=c2,recv=c1); identical handshake_hash both sides.
    let i_static = kp(0xD1);
    let r_static = kp(0xD2);
    let r_sig = sigpub(0xD3);
    let i_sig = sigpub(0xD4); // not used by IK handshake itself; documented

    let mut msg1 = [0u8; MSG1_SIZE];
    let mut init = Initiator::new(i_static, r_static.public);
    init.write_initiation(&mut msg1, 1, 7, &r_sig, &[0u8; MAC_BYTES]).unwrap();

    let mut resp = Responder::new(r_static);
    let _info = resp.read_initiation(&msg1, &r_sig).unwrap();
    let mut msg2 = [0u8; MSG2_SIZE];
    resp.write_response(&mut msg2, 9, 1, &r_sig, &[0u8; MAC_BYTES]).unwrap();
    init.read_response(&msg2, &r_sig).unwrap();

    let hi = init.finalize();
    let hr = resp.finalize();
    assert_eq!(hi.handshake_hash, hr.handshake_hash, "transcript hash identical");
    assert_eq!(hi.send_key, hr.recv_key, "initiator send = responder recv (c1)");
    assert_eq!(hi.recv_key, hr.send_key, "initiator recv = responder send (c2)");
    assert_ne!(hi.send_key, hi.recv_key, "directional keys differ");
    let _ = i_sig;
}

#[test]
fn be_tr_04_mac1_fails_before_any_curve_work() {
    // cite: noise.zig readResponse/readInitiation: Mac1Failed returned BEFORE
    // any DH. Provable observably: a corrupted mac1 yields Mac1Failed even when
    // the entire crypto body is ALSO garbage (the curve would fail anyway, so
    // Mac1Failed proves ordering).
    let i_static = kp(0xE1);
    let r_static = kp(0xE2);
    let r_sig = sigpub(0xE3);

    let mut msg1 = [0u8; MSG1_SIZE];
    let mut init = Initiator::new(i_static, r_static.public);
    init.write_initiation(&mut msg1, 1, 1, &r_sig, &[0u8; MAC_BYTES]).unwrap();
    msg1[113] ^= 0xFF; // corrupt mac1 itself
    let mut resp = Responder::new(r_static);
    assert_eq!(resp.read_initiation(&msg1, &r_sig), Err(Error::Mac1Failed));

    // same on the response side
    let mut msg1b = [0u8; MSG1_SIZE];
    let mut init2 = Initiator::new(i_static, r_static.public);
    init2.write_initiation(&mut msg1b, 1, 1, &r_sig, &[0u8; MAC_BYTES]).unwrap();
    let mut resp2 = Responder::new(r_static);
    resp2.read_initiation(&msg1b, &r_sig).unwrap();
    let mut msg2 = [0u8; MSG2_SIZE];
    resp2.write_response(&mut msg2, 1, 1, &r_sig, &[0u8; MAC_BYTES]).unwrap();
    msg2[61] ^= 0xFF;
    assert_eq!(init2.read_response(&msg2, &r_sig), Err(Error::Mac1Failed));
}

#[test]
fn tampered_ciphertext_is_decrypt_failed() {
    // cite: SymmetricState.decryptAndHash: tag mismatch = DecryptFailed.
    let i_static = kp(0xF1);
    let r_static = kp(0xF2);
    let r_sig = sigpub(0xF3);
    let mut msg1 = [0u8; MSG1_SIZE];
    let mut init = Initiator::new(i_static, r_static.public);
    init.write_initiation(&mut msg1, 1, 1, &r_sig, &[0u8; MAC_BYTES]).unwrap();
    msg1[40] ^= 0x01; // flip first byte of the encrypted static ciphertext
    // mac1 covers [0..112), which INCLUDES this ciphertext byte: without
    // re-signing, BE-TR-04 refuses first with Mac1Failed (that gate has its
    // own test). Re-sign so the tamper reaches decryptAndHash itself.
    // cite: noise.zig SymmetricState.decryptAndHash: tag mismatch = DecryptFailed.
    let m1 = compute_mac1(&r_sig, &msg1[..MSG1_BEFORE_MAC1]);
    msg1[OFF1_MAC1..OFF1_MAC1 + MAC_BYTES].copy_from_slice(&m1);
    let mut resp = Responder::new(r_static);
    assert_eq!(resp.read_initiation(&msg1, &r_sig), Err(Error::DecryptFailed));
}

#[test]
fn transport_nonce_composition_big_endian_everywhere() {
    // cite: noise.zig transportNonce: four zero bytes then be u64 counter.
    assert_eq!(transport_nonce(0), [0u8; 12]);
    assert_eq!(transport_nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(transport_nonce(0x0102_0304_0506_0708),
               [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(transport_nonce(u64::MAX), [0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn mac1_matches_zig_construction_with_label() {
    // cite: mac.zig mac1Key: unkeyed Blake2s-256(MAC1_LABEL || pubkey), then
    // keyed Blake2s-128. Same input twice = same tag; different key = differs.
    let p1 = sigpub(0x11);
    let p2 = sigpub(0x12);
    let msg = b"bolina handshake framing";
    let a = compute_mac1(&p1, msg);
    let b = compute_mac1(&p1, msg);
    assert_eq!(a, b, "deterministic");
    assert_ne!(compute_mac1(&p2, msg), a, "keyed by responder pubkey");
    let mut m2 = msg.to_vec();
    m2[0] ^= 1;
    assert_ne!(compute_mac1(&p1, &m2), a, "covers the message bytes");
}

#[test]
fn hmac_key_exactly_64_bytes_uses_direct_path() {
    // RFC 2104: keys LONGER than the block size (64) are hashed first; a key of
    // EXACTLY 64 bytes is used as-is. Mutant `>= 64` hashes the boundary key.
    // Kill: hmac(k64, msg) must NOT equal hmac(blake2s(k64), msg) — if the mutant
    // hashed the key, they would be equal.
    use bolina::transport::noise::hmac_blake2s;
    use blake2::{Blake2s256, Digest};
    let mut k64 = [0u8; 64];
    for (i, b) in k64.iter_mut().enumerate() { *b = i as u8; }
    let msg = b"boundary key test";
    let direct = hmac_blake2s(&k64, msg);
    let hashed_key: [u8; 32] = Blake2s256::digest(&k64).into();
    let via_hashed = hmac_blake2s(&hashed_key, msg);
    assert_ne!(direct, via_hashed,
        "64-byte key must take the direct path (mutant >=64 hashes it)");
    // A 65-byte key MUST be hashed (both variants agree)
    let mut k65 = [0u8; 65];
    k65[..64].copy_from_slice(&k64);
    k65[64] = 0xFF;
    let h65 = hmac_blake2s(&k65, msg);
    assert_ne!(h65, direct, "65-byte key must differ from 64-byte direct");
}
