//! W9 token: control plane auth token (token.zig port).
//!
//! One bearer token, generated from CSPRNG at first boot, stored 0600,
//! compared timing-safely. Fail-closed: absent/short/corrupt token refuses
//! every request except /healthz.

pub const TOKEN_BYTES: usize = 32;
pub const TOKEN_HEX_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    DiskError,
}

/// Generate 32 fresh random bytes.
pub fn generate() -> [u8; TOKEN_BYTES] {
    use rand_core::RngCore;
    let mut raw = [0u8; TOKEN_BYTES];
    rand_core::OsRng.fill_bytes(&mut raw);
    raw
}

/// Lowercase hex encoding, fixed width.
pub fn hex(token: &[u8; TOKEN_BYTES]) -> [u8; TOKEN_HEX_LEN] {
    let digits = b"0123456789abcdef";
    let mut out = [0u8; TOKEN_HEX_LEN];
    for (i, &b) in token.iter().enumerate() {
        out[i * 2] = digits[(b >> 4) as usize];
        out[i * 2 + 1] = digits[(b & 0xf) as usize];
    }
    out
}

/// Constant-time comparison over fixed-length hex.
pub fn verify(provided: &[u8], expected: &[u8; TOKEN_HEX_LEN]) -> bool {
    if provided.len() != TOKEN_HEX_LEN {
        return false;
    }
    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..TOKEN_HEX_LEN {
        diff |= provided[i] ^ expected[i];
    }
    diff == 0
}
