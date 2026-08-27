//! RFC Known-Answer Tests for every primitive Bolina uses (D-096-A).
//! Vectors are normative: any change here is a defect until proven otherwise.

use blake2::Digest;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hex_literal::hex;
use x25519_dalek::x25519;

/// RFC 7748 s6.1: Diffie-Hellman agreement produces the shared secret.
#[test]
fn rfc7748_x25519_diffie_hellman() {
    let alice_sk = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_pk   = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared   = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(x25519(alice_sk, bob_pk), shared);
}

/// RFC 7748 s6.1: scalar multiplication by base point matches published public.
#[test]
fn rfc7748_x25519_base_point_public() {
    let alice_sk  = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    // RFC 7748 s5: the base point is u=9, encoded LITTLE-ENDIAN over 32 bytes.
    // [9u8; 32] would be 0x0909.. which is an entirely different (invalid) point.
    let mut base = [0u8; 32];
    base[0] = 9;
    assert_eq!(x25519(alice_sk, base), alice_pub);
}

/// RFC 8032 s7.1 TEST 1: Ed25519 sign over empty message.
#[test]
fn rfc8032_ed25519_sign_verify() {
    let sk      = SigningKey::from_bytes(&hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    let want_pk = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let want_sig = hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    let vk = sk.verifying_key();
    assert_eq!(vk.to_bytes(), want_pk);

    let sig = sk.sign(b"");
    assert_eq!(sig.to_bytes(), want_sig);

    // Positive verify + one flipped-bit refusal (tag discipline, BE-SIG-01 spirit).
    vk.verify(b"", &sig).expect("valid signature must verify");
    let mut bad_bytes = want_sig;
    bad_bytes[0] ^= 0x01;
    let bad = Signature::from_bytes(&bad_bytes);
    assert!(vk.verify(b"", &bad).is_err(), "flipped signature bit must be refused");
}

/// RFC 8439 s2.8.2: ChaCha20-Poly1305 AEAD encryption with AAD.
#[test]
fn rfc8439_chacha20poly1305_aead() {
    let key  = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let ntry = Nonce::from_slice(&hex!("070000004041424344454647"));
    let aad  = hex!("50515253c0c1c2c3c4c5c6c7");
    let ptxt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let want_ctxt = hex!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116");
    let want_tag  = hex!("1ae10b594f09e26a7e902ecbd0600691");

    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut combined = Vec::with_capacity(want_ctxt.len() + 16);
    combined.extend_from_slice(&want_ctxt);
    combined.extend_from_slice(&want_tag);
    assert_eq!(
        cipher.encrypt(ntry, Payload { msg: ptxt.as_slice(), aad: &aad }).unwrap(),
        combined,
        "seal must match RFC bytes exactly (ct||tag)"
    );
    let opened = cipher.decrypt(ntry, Payload { msg: &combined, aad: &aad }).unwrap();
    assert_eq!(opened, ptxt);
}

/// RFC 7693 B.3 / Appendix: BLAKE2s-256("abc").
#[test]
fn rfc7693_blake2s_256_of_abc() {
    let want = hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    let mut h = blake2::Blake2s256::new();
    h.update(b"abc");
    assert_eq!(h.finalize().as_slice(), &want);
}

/// Fingerprint contract (keys.fingerprint on the Zig side): hash at FULL width, then
/// slice — not a shorter BLAKE2 parameterisation. The first 8 bytes feed the hex fp.
#[test]
fn blake2s_digest_truncation_first8_is_fingerprint_shape() {
    let want_full = hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    let mut h = blake2::Blake2s256::new();
    h.update(b"abc");
    let d = h.finalize();
    assert_eq!(d.as_slice(), &want_full);
    assert_eq!(&d[..8], &want_full[..8]);
}
