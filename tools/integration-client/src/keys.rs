//! Client identity, derived deterministically from the round seed.
//! Same seed => byte-identical keys => same fingerprint. This is the
//! reproducibility contract the soak relies on (design section 6).

use bolina::transport::noise::KeyPair;
use ed25519_dalek::SigningKey;
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
