//! Noise_IK_25519_ChaChaPoly_BLAKE2s: the handshake machine. Byte-exact port
//! of src/noise.zig (protocol name, HKDF, symmetric state, msg1 144B / msg2
//! 92B layouts, BE-TR-04 mac1-first, G2-fixed response index semantics).
//! SPEC 2.2 / 4.1a.

use super::mac1;
use super::mac1::MAC_BYTES;
use blake2::digest::Digest;
use blake2::Blake2s256;
use chacha20poly1305::aead::{AeadInPlace, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as AeadKeyInit, Nonce};
use rand_core::OsRng;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub const DHLEN: usize = 32;
pub const HASHLEN: usize = 32;
pub const KEYLEN: usize = 32;
pub const TAGLEN: usize = 16;
pub const NONCELEN: usize = 12;
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

// SPEC 4.1a message sizes and mac1 coverage boundaries (framing + crypto body;
// the framing itself is NOT transcript material).
pub const MSG1_SIZE: usize = 144;
pub const MSG2_SIZE: usize = 92;
pub const MSG1_BEFORE_MAC1: usize = 112;
pub const MSG2_BEFORE_MAC1: usize = 60;

pub const OFF1_SENDER_INDEX: usize = 4;
pub const OFF1_EPHEMERAL: usize = 8;
pub const OFF1_ENC_STATIC: usize = 40; // 48 bytes (32 + tag)
pub const OFF1_ENC_TIMESTAMP: usize = 88; // 24 bytes (8 + tag)
pub const OFF1_MAC1: usize = 112;
pub const OFF1_MAC2: usize = 128;

pub const OFF2_SENDER_INDEX: usize = 4;
pub const OFF2_RECEIVER_INDEX: usize = 8; // G2 fix: echo of the INITIATOR index
pub const OFF2_EPHEMERAL: usize = 12;
pub const OFF2_ENC_NOTHING: usize = 44; // 16 bytes (0 + tag)
pub const OFF2_MAC1: usize = 60;
pub const OFF2_MAC2: usize = 76;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Mac1Failed,
    DecryptFailed,
    IdentityPoint,
}

/// Result of a completed handshake: the two transport keys and the transcript
/// hash (which binds the mutual cert exchange downstream, BE-TR-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResult {
    pub send_key: [u8; KEYLEN],
    pub recv_key: [u8; KEYLEN],
    pub handshake_hash: [u8; HASHLEN],
}

/// HMAC-BLAKE2s-256, spelled out: the hmac crate needs an Eager hash and
/// Blake2s is Lazy, so RFC 2104 is implemented directly over the 64-byte
/// BLAKE2s block. Byte-identical to std.crypto.auth.hmac.Blake2s256.
fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Blake2s256::new();
        Digest::update(&mut h, key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Blake2s256::new();
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    Digest::update(&mut inner, ipad);
    Digest::update(&mut inner, data);
    let mut outer = Blake2s256::new();
    Digest::update(&mut outer, opad);
    Digest::update(&mut outer, &inner.finalize());
    outer.finalize().into()
}

/// ChaCha20-Poly1305 nonce for any session counter: four zero bytes then the
/// big-endian u64 counter (SPEC 2.2 "big-endian everywhere").
pub fn transport_nonce(counter: u64) -> [u8; NONCELEN] {
    let mut nb = [0u8; NONCELEN];
    nb[4..].copy_from_slice(&counter.to_be_bytes());
    nb
}

// HKDF (Noise): temp_key = HMAC(ck, ikm); out1 = HMAC(temp_key, 0x01);
// out2 = HMAC(temp_key, out1 || 0x02). The counter byte is the only domain
// separation, which is the Noise definition.
fn hmac_pair(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hmac_blake2s(key, data)
}

fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp_key = hmac_pair(ck, ikm);
    let o1 = hmac_pair(&temp_key, &[1u8]);
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&o1);
    buf[32] = 2;
    let o2 = hmac_pair(&temp_key, &buf);
    (o1, o2)
}

/// DH over X25519 with the all-zero (identity) rejection the Zig dh() enforces.
fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; DHLEN], Error> {
    let shared = x25519(*sk, *pk);
    if shared == [0u8; 32] {
        return Err(Error::IdentityPoint);
    }
    Ok(shared)
}

/// The Noise symmetric state (Zig SymmetricState folded: h, ck, k, n, has_key).
pub struct SymmetricState {
    pub h: [u8; HASHLEN],
    pub ck: [u8; HASHLEN],
    k: [u8; KEYLEN],
    n: u64,
    has_key: bool,
}

impl SymmetricState {
    /// h = BLAKE2s-256(protocol name) (longer than HASHLEN, so hashed);
    /// ck = h; no key. Prologue is empty (SPEC declares none).
    pub fn init() -> Self {
        let mut h = [0u8; HASHLEN];
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, PROTOCOL_NAME);
        h.copy_from_slice(&hasher.finalize());
        SymmetricState { h, ck: h, k: [0u8; KEYLEN], n: 0, has_key: false }
    }

    /// h = BLAKE2s(h || data).
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, &self.h);
        Digest::update(&mut hasher, data);
        self.h.copy_from_slice(&hasher.finalize());
    }

    /// ck, k = HKDF(ck, ikm, 2); reset the nonce; key now present.
    pub fn mix_key(&mut self, ikm: &[u8; DHLEN]) {
        let (o1, o2) = hkdf2(&self.ck, ikm);
        self.ck = o1;
        self.k = o2;
        self.n = 0;
        self.has_key = true;
    }

    /// AEAD-encrypt pt under k with ad = h at out[0..pt.len], append the tag,
    /// advance the nonce, MixHash the ciphertext-with-tag. No-key branch passes
    /// the plaintext through (implemented for correctness; never hit in IK).
    pub fn encrypt_and_hash(&mut self, out: &mut [u8], pt: &[u8]) {
        if self.has_key {
            let (ct, tag_out) = out.split_at_mut(pt.len());
            ct.copy_from_slice(pt);
            let cipher = ChaCha20Poly1305::new((&self.k).into());
            let payload = Payload { msg: pt, aad: &self.h };
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&transport_nonce(self.n)), payload.aad, ct)
                .expect("in-place encrypt of sized buffer");
            tag_out.copy_from_slice(&tag);
            self.n += 1;
            let mixed_len = pt.len() + TAGLEN;
            let mixed: Vec<u8> = out[..mixed_len].to_vec();
            self.mix_hash(&mixed);
        } else {
            out[..pt.len()].copy_from_slice(pt);
            self.mix_hash(&out[..pt.len()]);
        }
    }

    /// The inverse. Tag mismatch = DecryptFailed; nonce advances and the
    /// ciphertext-with-tag mixes exactly as on encrypt.
    pub fn decrypt_and_hash(&mut self, out: &mut [u8], ct: &[u8]) -> Result<(), Error> {
        if self.has_key {
            let pt_len = ct.len() - TAGLEN;
            let (body, tag) = ct.split_at(pt_len);
            let mut buf = body.to_vec();
            let cipher = ChaCha20Poly1305::new((&self.k).into());
            let payload = Payload { msg: &[], aad: &self.h };
            cipher
                .decrypt_in_place_detached(Nonce::from_slice(&transport_nonce(self.n)), payload.aad, &mut buf, tag.into())
                .map_err(|_| Error::DecryptFailed)?;
            out[..pt_len].copy_from_slice(&buf);
            self.n += 1;
            self.mix_hash(ct);
        } else {
            out[..ct.len()].copy_from_slice(ct);
            self.mix_hash(ct);
        }
        Ok(())
    }

    /// Two transport keys from HKDF(ck, "", 2). o1 = initiator's sending key.
    pub fn split(&self) -> ([u8; KEYLEN], [u8; KEYLEN]) {
        hkdf2(&self.ck, &[])
    }
}

#[derive(Clone, Copy)]
pub struct KeyPair {
    pub secret: [u8; DHLEN],
    pub public: [u8; DHLEN],
}

impl KeyPair {
    pub fn from_secret(secret: [u8; DHLEN]) -> Self {
        KeyPair { secret, public: x25519(secret, X25519_BASEPOINT_BYTES) }
    }
}

/// Noise_IK initiator (Zig Initiator: e, es, s, ss, encrypted timestamp).
pub struct Initiator {
    eph_kp: KeyPair,
    static_kp: KeyPair,
    re: [u8; DHLEN],
    responder_static_pub: [u8; DHLEN],
    sym: SymmetricState,
}

impl Initiator {
    pub fn new(static_kp: KeyPair, responder_static_pub: [u8; DHLEN]) -> Self {
        // Noise IK pre-message: the responder static is mixed into h once at
        // init (Zig Initiator.init parity). Missing this diverges h from
        // message 1 onward - invisible to Rust-Rust roundtrips, fatal live.
        let mut sym = SymmetricState::init();
        sym.mix_hash(&responder_static_pub);
        Initiator { eph_kp: KeyPair::from_secret([0; 32]), static_kp, re: [0; 32], responder_static_pub, sym }
    }

    /// Write the 144-byte initiation. mac2_cookie is zeros when none is held.
    pub fn write_initiation(
        &mut self,
        out: &mut [u8; MSG1_SIZE],
        sender_index: u32,
        timestamp_ms: u64,
        responder_sig_pubkey: &[u8; 32],
        mac2_cookie: &[u8; MAC_BYTES],
    ) -> Result<(), Error> {
        // e: fresh ephemeral, written and hashed.
        let eph_secret: [u8; DHLEN] = {
            use rand_core::RngCore;
            let mut s = [0u8; DHLEN];
            OsRng.fill_bytes(&mut s);
            s
        };
        self.eph_kp = KeyPair::from_secret(eph_secret);
        out[OFF1_EPHEMERAL..OFF1_EPHEMERAL + DHLEN].copy_from_slice(&self.eph_kp.public);
        self.sym.mix_hash(&self.eph_kp.public);

        // es: DH(e_i, s_R).
        let sh = dh(&self.eph_kp.secret, &self.responder_static_pub)?;
        self.sym.mix_key(&sh);

        // s: initiator static, encrypted and hashed.
        let mut buf = [0u8; DHLEN + TAGLEN];
        self.sym.encrypt_and_hash(&mut buf, &self.static_kp.public);
        out[OFF1_ENC_STATIC..OFF1_ENC_STATIC + DHLEN + TAGLEN].copy_from_slice(&buf);

        // ss: DH(s_i, s_R).
        let sh2 = dh(&self.static_kp.secret, &self.responder_static_pub)?;
        self.sym.mix_key(&sh2);

        // Encrypted timestamp (SPEC 2.2, u64 ms, big-endian).
        let mut ts_pt = [0u8; 8];
        ts_pt.copy_from_slice(&timestamp_ms.to_be_bytes());
        let mut ts_buf = [0u8; 8 + TAGLEN];
        self.sym.encrypt_and_hash(&mut ts_buf, &ts_pt);
        out[OFF1_ENC_TIMESTAMP..OFF1_ENC_TIMESTAMP + 8 + TAGLEN].copy_from_slice(&ts_buf);

        // Framing + DoS proofs (framing is not transcript material).
        out[0] = 1;
        out[1..OFF1_SENDER_INDEX].fill(0);
        out[OFF1_SENDER_INDEX..OFF1_SENDER_INDEX + 4].copy_from_slice(&sender_index.to_be_bytes());
        let m1 = mac1::compute_mac1(responder_sig_pubkey, &out[..MSG1_BEFORE_MAC1]);
        out[OFF1_MAC1..OFF1_MAC1 + MAC_BYTES].copy_from_slice(&m1);
        out[OFF1_MAC2..OFF1_MAC2 + MAC_BYTES].copy_from_slice(mac2_cookie);
        Ok(())
    }

    /// Read the 92-byte response: mac1 FIRST (BE-TR-04), then e, ee, se, empty
    /// encrypted payload. The receiver index at OFF2 is the echo of OUR index
    /// (G2 fix, SPEC 4.1a); the sender index is the responder's own slot.
    pub fn read_response(
        &mut self,
        msg2: &[u8; MSG2_SIZE],
        responder_sig_pubkey: &[u8; 32],
    ) -> Result<(), Error> {
        let m1_in: [u8; MAC_BYTES] = msg2[OFF2_MAC1..OFF2_MAC1 + MAC_BYTES].try_into().unwrap();
        if !mac1::verify_mac1(responder_sig_pubkey, &msg2[..MSG2_BEFORE_MAC1], &m1_in) {
            return Err(Error::Mac1Failed);
        }

        // e: responder ephemeral, hashed.
        let eph_r: [u8; DHLEN] = msg2[OFF2_EPHEMERAL..OFF2_EPHEMERAL + DHLEN].try_into().unwrap();
        self.re = eph_r;
        self.sym.mix_hash(&eph_r);

        // ee: DH(e_i, e_R).
        let ee = dh(&self.eph_kp.secret, &self.re)?;
        self.sym.mix_key(&ee);

        // se: DH(s_i, e_R).
        let se = dh(&self.static_kp.secret, &self.re)?;
        self.sym.mix_key(&se);

        // Empty encrypted payload: tag-only.
        let mut nothing = [0u8; TAGLEN];
        self.sym.decrypt_and_hash(&mut nothing, &msg2[OFF2_ENC_NOTHING..OFF2_ENC_NOTHING + TAGLEN])
    }

    /// Split: the initiator sends under c1 and receives under c2.
    pub fn finalize(self) -> HandshakeResult {
        let (c1, c2) = self.sym.split();
        HandshakeResult { send_key: c1, recv_key: c2, handshake_hash: self.sym.h }
    }
}

/// Noise_IK responder (Zig Responder).
pub struct Responder {
    static_kp: KeyPair,
    eph_kp: KeyPair,
    re: [u8; DHLEN],
    remote_static_pub: [u8; DHLEN],
    sym: SymmetricState,
}

/// What the responder learns from a valid initiation. The anti-replay policy
/// on `timestamp_ms` lives in the session layer, not here.
#[derive(Debug, PartialEq, Eq)]
pub struct InitiationInfo {
    pub sender_index: u32,
    pub initiator_static_pub: [u8; DHLEN],
    pub timestamp_ms: u64,
}

impl Responder {
    pub fn new(static_kp: KeyPair) -> Self {
        // Pre-message: the responder mixes its OWN static public (IK pattern).
        let mut sym = SymmetricState::init();
        sym.mix_hash(&static_kp.public);
        Responder { static_kp, eph_kp: KeyPair::from_secret([0; 32]), re: [0; 32], remote_static_pub: [0; 32], sym }
    }

    /// Read the 144-byte initiation: mac1 FIRST, then e, es, s, ss, timestamp.
    pub fn read_initiation(
        &mut self,
        msg1: &[u8; MSG1_SIZE],
        own_sig_pubkey: &[u8; 32],
    ) -> Result<InitiationInfo, Error> {
        let m1_in: [u8; MAC_BYTES] = msg1[OFF1_MAC1..OFF1_MAC1 + MAC_BYTES].try_into().unwrap();
        if !mac1::verify_mac1(own_sig_pubkey, &msg1[..MSG1_BEFORE_MAC1], &m1_in) {
            return Err(Error::Mac1Failed);
        }

        // e: hashed; captured for es.
        let eph_i: [u8; DHLEN] = msg1[OFF1_EPHEMERAL..OFF1_EPHEMERAL + DHLEN].try_into().unwrap();
        self.re = eph_i;
        self.sym.mix_hash(&eph_i);

        // es: DH(s_R, e_i).
        let es = dh(&self.static_kp.secret, &self.re)?;
        self.sym.mix_key(&es);

        // s: initiator static, decrypted; captured for ss.
        let mut static_i = [0u8; DHLEN];
        self.sym.decrypt_and_hash(&mut static_i, &msg1[OFF1_ENC_STATIC..OFF1_ENC_STATIC + DHLEN + TAGLEN])?;
        self.remote_static_pub = static_i;

        // ss: DH(s_R, s_I).
        let ss = dh(&self.static_kp.secret, &self.remote_static_pub)?;
        self.sym.mix_key(&ss);

        // Encrypted timestamp: decrypted into the transcript.
        let mut ts = [0u8; 8];
        self.sym.decrypt_and_hash(&mut ts, &msg1[OFF1_ENC_TIMESTAMP..OFF1_ENC_TIMESTAMP + 8 + TAGLEN])?;
        let timestamp_ms = u64::from_be_bytes(ts);

        let sender_index = u32::from_be_bytes(msg1[OFF1_SENDER_INDEX..OFF1_SENDER_INDEX + 4].try_into().unwrap());
        Ok(InitiationInfo { sender_index, initiator_static_pub: static_i, timestamp_ms })
    }

    /// Write the 92-byte response: e, ee, se, empty encrypted payload. The
    /// sender index is OUR slot; the receiver index ECHOES the initiator's
    /// (SPEC 4.1a; the layout the G2 interop proved load-bearing).
    pub fn write_response(
        &mut self,
        out: &mut [u8; MSG2_SIZE],
        sender_index: u32,
        receiver_index: u32,
        own_sig_pubkey: &[u8; 32],
        mac2_cookie: &[u8; MAC_BYTES],
    ) -> Result<(), Error> {
        let eph_secret: [u8; DHLEN] = {
            use rand_core::RngCore;
            let mut s = [0u8; DHLEN];
            OsRng.fill_bytes(&mut s);
            s
        };
        self.eph_kp = KeyPair::from_secret(eph_secret);
        out[0] = 2;
        out[1..OFF2_SENDER_INDEX].fill(0);
        out[OFF2_SENDER_INDEX..OFF2_SENDER_INDEX + 4].copy_from_slice(&sender_index.to_be_bytes());
        out[OFF2_RECEIVER_INDEX..OFF2_RECEIVER_INDEX + 4].copy_from_slice(&receiver_index.to_be_bytes());
        out[OFF2_EPHEMERAL..OFF2_EPHEMERAL + DHLEN].copy_from_slice(&self.eph_kp.public);
        self.sym.mix_hash(&self.eph_kp.public);

        // ee: DH(e_R, e_I).
        let ee = dh(&self.eph_kp.secret, &self.re)?;
        self.sym.mix_key(&ee);

        // se: DH(e_R, s_I).
        let se = dh(&self.eph_kp.secret, &self.remote_static_pub)?;
        self.sym.mix_key(&se);

        // Empty encrypted payload.
        let mut nothing = [0u8; TAGLEN];
        self.sym.encrypt_and_hash(&mut nothing, &[]);
        out[OFF2_ENC_NOTHING..OFF2_ENC_NOTHING + TAGLEN].copy_from_slice(&nothing);

        // DoS proofs.
        let m1 = mac1::compute_mac1(own_sig_pubkey, &out[..MSG2_BEFORE_MAC1]);
        out[OFF2_MAC1..OFF2_MAC1 + MAC_BYTES].copy_from_slice(&m1);
        out[OFF2_MAC2..OFF2_MAC2 + MAC_BYTES].copy_from_slice(mac2_cookie);
        Ok(())
    }

    /// Split: the responder sends under c2 and receives under c1 (the swap of
    /// the initiator's pair).
    pub fn finalize(self) -> HandshakeResult {
        let (c1, c2) = self.sym.split();
        HandshakeResult { send_key: c2, recv_key: c1, handshake_hash: self.sym.h }
    }

}
