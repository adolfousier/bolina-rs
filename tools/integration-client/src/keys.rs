//! Client identity, derived deterministically from the round seed.
//! Same seed => byte-identical keys => same fingerprint. This is the
//! reproducibility contract the soak relies on (design section 6).

use bolina::codec;
use bolina::transport::binding::ROLE_AGENT;
use bolina::transport::noise::KeyPair;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub struct ClientKeys {
    /// X25519 static keypair - Noise_IK initiator static (F1 pins this).
    pub kex: KeyPair,
    /// Ed25519 signing identity (envelopes + binding frame).
    pub sig: SigningKey,
    /// Grant approver subkey (ladder A plays approver for its own grant).
    pub approver: SigningKey,
    /// Throwaway CA that signs the client cert; its pub goes to the
    /// daemon's trust set via the soak wrapper (task 8 wiring).
    pub ca: SigningKey,
}

/// Four ChaCha8 draws in fixed order: kex, sig, approver, ca.
pub fn seeded(seed: u64) -> ClientKeys {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut kex_secret = [0u8; 32];
    rng.fill_bytes(&mut kex_secret);
    let mut sig_seed = [0u8; 32];
    rng.fill_bytes(&mut sig_seed);
    let mut approver_seed = [0u8; 32];
    rng.fill_bytes(&mut approver_seed);
    let mut ca_seed = [0u8; 32];
    rng.fill_bytes(&mut ca_seed);
    ClientKeys {
        kex: KeyPair::from_secret(kex_secret),
        sig: SigningKey::from_bytes(&sig_seed),
        approver: SigningKey::from_bytes(&approver_seed),
        ca: SigningKey::from_bytes(&ca_seed),
    }
}

/// Self-CA'd agent cert for the binding frame (shared by all ladders). cert.kex_pubkey equals the
/// handshake static (F1); whether the daemon's trust set accepts this CA
/// is task-8 wiring - the frame format is what this proves.
pub fn build_cert(ck: &ClientKeys, nb: u64, na: u64) -> Vec<u8> {
    let sig_pub = ck.sig.verifying_key().to_bytes();
    let name = b"integration-client";
    let mut tbs = Vec::with_capacity(160);
    tbs.push(3); // version
    tbs.push(ROLE_AGENT); // agent: no quorum requirement (BE-ID-04 n/a)
    tbs.extend_from_slice(&sig_pub);
    tbs.extend_from_slice(&ck.kex.public);
    tbs.extend_from_slice(&nb.to_be_bytes());
    tbs.extend_from_slice(&na.to_be_bytes());
    tbs.extend_from_slice(&(name.len() as u16).to_be_bytes());
    tbs.extend_from_slice(name);
    tbs.push(1); // scope_count: v3-with-empty-scopes is deny-all (D-085 R4)
    tbs.extend_from_slice(&[0u8; 8]); // scope id 0 (LEN_SCOPE_ID = 8)
    // CA sig: tag-then-tbs over DOMAIN_CERT (binding sheet invariant 2 shape)
    let sig_input = [vec![codec::DOMAIN_CERT], tbs.clone()].concat();
    let ca_sig = ck.ca.sign(&sig_input);
    let mut out = tbs;
    out.push(1); // ca_sig_count
    out.extend_from_slice(&ck.ca.verifying_key().to_bytes());
    out.extend_from_slice(ca_sig.to_bytes().as_slice());
    out
}

