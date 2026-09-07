//! W9 token: control plane auth token (token.zig port).
//!
//! One bearer token, generated from CSPRNG at first boot, stored 0600,
//! compared timing-safely. Fail-closed: absent/short/corrupt token refuses
//! every request except /healthz.
#![allow(dead_code)]

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

// ---------------------------------------------------------------------------
// File I/O (token.zig: save/load with 0600 permissions)
// ---------------------------------------------------------------------------

/// Save a token as hex to a file with 0600 permissions.
///
/// Creates the file if it doesn't exist, overwrites if it does.
/// Returns DiskError on any I/O failure.
pub fn save(path: &str, token: &[u8; TOKEN_BYTES]) -> Result<(), TokenError> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let hex_bytes = hex(token);

    #[cfg(unix)]
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut file = opts.open(path).map_err(|_| TokenError::DiskError)?;
        use std::io::Write;
        file.write_all(&hex_bytes).map_err(|_| TokenError::DiskError)?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, &hex_bytes).map_err(|_| TokenError::DiskError)?;
    }

    Ok(())
}

/// Load a token from a hex file.
///
/// Returns None if:
/// - File doesn't exist (absent)
/// - File is shorter than TOKEN_HEX_LEN bytes (short)
/// - File contains non-hex bytes (corrupt)
///
/// Fail-closed: any ambiguity returns None.
pub fn load(path: &str) -> Option<[u8; TOKEN_BYTES]> {
    use std::fs;

    let data = fs::read(path).ok()?;
    if data.len() != TOKEN_HEX_LEN {
        return None; // absent or short
    }

    // Decode hex
    let mut token = [0u8; TOKEN_BYTES];
    for i in 0..TOKEN_BYTES {
        let hi = hex_val(data[i * 2])?;
        let lo = hex_val(data[i * 2 + 1])?;
        token[i] = (hi << 4) | lo;
    }
    Some(token)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None, // corrupt
    }
}
