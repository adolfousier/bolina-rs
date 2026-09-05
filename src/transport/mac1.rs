//! mac1: the DoS gate. Key derivation is an unkeyed BLAKE2s-256 over the label
//! concatenated with the responder's Ed25519 public key; the MAC itself is
//! BLAKE2s-128 keyed with that digest over the header bytes preceding mac1
//! (RFC 7693 keyed mode). BE-TR-04: the caller verifies mac1 BEFORE any
//! X25519, so a flood costs one hash, not a curve operation.
//! Port of src/mac.zig mac1Key/computeMac1/verifyMac1 (labels verbatim).

use blake2::digest::{KeyInit, Mac};
use blake2::digest::consts::U16;
use blake2::{Blake2s256, Blake2sMac, Digest};

pub const MAC_BYTES: usize = 16;
pub const MAC1_LABEL: &[u8] = b"bolina-mac1-v2";

/// key = BLAKE2s-256(MAC1_LABEL || responder_sig_pubkey), unkeyed, two chunks.
fn mac1_key(responder_sig_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    Digest::update(&mut h, MAC1_LABEL);
    Digest::update(&mut h, responder_sig_pubkey);
    h.finalize().into()
}

/// mac1 = BLAKE2s-128(key = mac1_key, msg = bytes preceding mac1 on the wire).
pub fn compute_mac1(responder_sig_pubkey: &[u8; 32], msg_preceding: &[u8]) -> [u8; MAC_BYTES] {
    use blake2::digest::Update;
    let key = mac1_key(responder_sig_pubkey);
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&key)
        .expect("BLAKE2s accepts 32-byte keys");
    Update::update(&mut mac, msg_preceding);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_BYTES];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time verify. True only on exact match; the caller MUST run this
/// before any X25519 and silently drop on failure (BE-TR-04).
pub fn verify_mac1(
    responder_sig_pubkey: &[u8; 32],
    msg_preceding: &[u8],
    received: &[u8; MAC_BYTES],
) -> bool {
    use subtle::ConstantTimeEq;
    compute_mac1(responder_sig_pubkey, msg_preceding)
        .ct_eq(received)
        .into()
}

// ---------------------------------------------------------------------------
// Cookie (mac2) layer: anti-amplification under load.
// ---------------------------------------------------------------------------

pub const KEY_BYTES: usize = 32;
pub const COOKIE_ROTATE_MS: u64 = 120_000; // 2 minutes

pub struct CookieSecret {
    pub secret: [u8; KEY_BYTES],
    pub created_ms: u64,
}

impl CookieSecret {
    pub fn new(initial_secret: [u8; KEY_BYTES], now_ms: u64) -> Self {
        Self { secret: initial_secret, created_ms: now_ms }
    }

    /// True once the secret is COOKIE_ROTATE_MS old.
    pub fn needs_rotate(&self, now_ms: u64) -> bool {
        now_ms.wrapping_sub(self.created_ms) >= COOKIE_ROTATE_MS
    }

    /// Replace secret with new material and stamp it now.
    pub fn rotate(&mut self, new_secret: [u8; KEY_BYTES], now_ms: u64) {
        self.secret = new_secret;
        self.created_ms = now_ms;
    }

    /// Issue a cookie: BLAKE2s-128(keyed with secret) over source_addr.
    pub fn issue_cookie(&self, source_addr: &[u8]) -> [u8; MAC_BYTES] {
        use blake2::digest::Update;
        let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(&self.secret)
            .expect("BLAKE2s accepts 32-byte keys");
        Update::update(&mut mac, source_addr);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; MAC_BYTES];
        out.copy_from_slice(&tag);
        out
    }

    /// Constant-time cookie verify.
    pub fn verify_cookie(&self, source_addr: &[u8], received: [u8; MAC_BYTES]) -> bool {
        use subtle::ConstantTimeEq;
        self.issue_cookie(source_addr).ct_eq(&received).into()
    }
}
