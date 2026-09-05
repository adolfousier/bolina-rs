//! keys.rs — node key material facade (W10).
//! Sheet: specs/keys.md - Zig: src/keys.zig (194 lines, keys_test.zig 8 named).
//!
//! Single-implementation rule (BE-RES-06): fingerprint DELEGATES to
//! transport::resolver::executor_fp - never a second hex digester.
//!
//! Invariants (each pinned by a named test below):
//! - first run generates, second reloads byte-identical (D-018 anti-zeroed)
//! - secret files 0600, dir 0700
//! - tampered static.pub => PubMismatch, DISTINCT from missing-file
//! - truncated secret file = corruption, NEVER silent regeneration
//! - cert.bin loads verbatim up to MAX_CERT; ABSENT = len 0 unbound-accept
//! - CA pubs load ca0.pub..ca7.pub in LABEL ORDER (order = cert sig slots)

use crate::transport::resolver::executor_fp;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub const MAX_CAS: usize = 8;
pub const MAX_CERT: usize = 1024;
pub const KEY_LEN: usize = 32;
pub const MAX_PATH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysError {
    DataDirUnwritable,
    KeyFileCorrupt,
    PubMismatch,
    CertTooLarge,
    DiskError,
}

pub struct Keys {
    /// X25519 static secret (transport).
    pub secret_static: [u8; KEY_LEN],
    /// X25519 static public.
    pub pub_static: [u8; KEY_LEN],
    /// Ed25519 signing key (signing identity).
    pub sig_key: SigningKey,
    /// cert.bin bytes, empty = unbound-accept mode (never an error).
    pub cert: Vec<u8>,
    /// CA pubs in LABEL ORDER ca0..ca7 (order matters downstream).
    pub ca_pubs: Vec<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("pub_static", &self.pub_static)
            .field("cert_len", &self.cert.len())
            .field("ca_count", &self.ca_pubs.len())
            .finish_non_exhaustive()
    }
}

impl Keys {
    pub fn sig_pub(&self) -> [u8; KEY_LEN] {
        self.sig_key.verifying_key().to_bytes()
    }
}

/// fingerprint: hex16 of BLAKE2s-256(pubkey)[0..8] - DELEGATES to
/// executor_fp (same value the resolver FP uses; BE-RES-06).
pub fn fingerprint(pubkey: &[u8]) -> [u8; 16] {
    executor_fp(pubkey)
}

/// readKeyFile: found -> Some(bytes); absent -> None (false in Zig).
/// File exists but wrong size => KeyFileCorrupt (truncated = corruption,
/// NOT silent regeneration).
fn read_key_file(path: &Path, expect: usize) -> Result<Option<Vec<u8>>, KeysError> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != expect {
                return Err(KeysError::KeyFileCorrupt);
            }
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(KeysError::DiskError),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), KeysError> {
    fs::write(path, bytes).map_err(|_| KeysError::DiskError)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| KeysError::DiskError)?;
    Ok(())
}

fn ensure_dir(path: &Path) -> Result<(), KeysError> {
    fs::create_dir_all(path).map_err(|_| KeysError::DataDirUnwritable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| KeysError::DataDirUnwritable)?;
    Ok(())
}

/// loadOrGenerate: first run generates real X25519+Ed25519 material;
/// second run reloads byte-identical. Tampered pub cross-check =>
/// PubMismatch (timing-safe compare over the derived secret).
pub fn load_or_generate(data_dir: &Path) -> Result<Keys, KeysError> {
    ensure_dir(data_dir)?;
    let secret_path = data_dir.join("secret.key");
    let pub_path = data_dir.join("static.pub");
    let sig_path = data_dir.join("sig.key");

    let secret_static: [u8; KEY_LEN] = match read_key_file(&secret_path, KEY_LEN)? {
        Some(b) => b.try_into().map_err(|_| KeysError::KeyFileCorrupt)?,
        None => {
            let mut s = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut s);
            write_private(&secret_path, &s)?;
            s
        }
    };
    let pub_static = x25519(secret_static, X25519_BASEPOINT_BYTES);

    // Stored pub cross-checked against derived-from-secret; tamper =>
    // PubMismatch, a distinct fatal (never silently accepted).
    match read_key_file(&pub_path, KEY_LEN)? {
        Some(stored) => {
            if !timing_safe_eq(&stored, &pub_static) {
                return Err(KeysError::PubMismatch);
            }
        }
        None => write_private(&pub_path, &pub_static)?,
    }

    let sig_key = match read_key_file(&sig_path, KEY_LEN)? {
        Some(b) => {
            let arr: [u8; KEY_LEN] = b.try_into().map_err(|_| KeysError::KeyFileCorrupt)?;
            SigningKey::from_bytes(&arr)
        }
        None => {
            let mut seed = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut seed);
            let k = SigningKey::from_bytes(&seed);
            write_private(&sig_path, k.to_bytes().as_slice())?;
            k
        }
    };

    // cert.bin: verbatim up to MAX_CERT; absent = unbound-accept (len 0).
    let cert = match fs::read(data_dir.join("cert.bin")) {
        Ok(c) => {
            if c.len() > MAX_CERT {
                return Err(KeysError::CertTooLarge);
            }
            c
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(KeysError::DiskError),
    };

    // CA pubs in LABEL ORDER: ca/ca0.pub .. ca/ca7.pub. A label PRESENT but
    // wrong size is corruption; MISSING ends the prefix (shrink allowed).
    let ca_dir = data_dir.join("ca");
    let mut ca_pubs = Vec::with_capacity(MAX_CAS);
    for i in 0..MAX_CAS {
        let p = ca_dir.join(format!("ca{}.pub", i));
        match fs::read(&p) {
            Ok(b) => {
                if b.len() != KEY_LEN {
                    return Err(KeysError::KeyFileCorrupt);
                }
                let mut k = [0u8; KEY_LEN];
                k.copy_from_slice(&b);
                ca_pubs.push(k);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(KeysError::DiskError),
        }
    }

    Ok(Keys { secret_static, pub_static, sig_key, cert, ca_pubs })
}

fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().to_path_buf();
        (d, p)
    }

    /// keys_test.zig:69 - first run generates; second reloads byte-identical.
    #[test]
    fn be_res_06_keys_reload_byte_identical() {
        let (_d, dir) = tmpdir();
        let k1 = load_or_generate(&dir).unwrap();
        let k2 = load_or_generate(&dir).unwrap();
        assert_eq!(k1.secret_static, k2.secret_static);
        assert_eq!(k1.pub_static, k2.pub_static);
        assert_eq!(k1.sig_key.to_bytes(), k2.sig_key.to_bytes());
        // never zeroed keys (D-018)
        assert_ne!(k1.secret_static, [0u8; KEY_LEN]);
    }

    /// keys_test.zig:96 - tampered static.pub is a DISTINCT fatal.
    #[test]
    fn be_res_06_tampered_pub_is_pub_mismatch_distinct_from_missing() {
        let (_d, dir) = tmpdir();
        load_or_generate(&dir).unwrap();
        // tamper the stored pub
        let pub_path = dir.join("static.pub");
        let mut b = fs::read(&pub_path).unwrap();
        b[0] ^= 0xff;
        fs::write(&pub_path, &b).unwrap();
        let err = load_or_generate(&dir).unwrap_err();
        assert_eq!(err, KeysError::PubMismatch);
        assert_ne!(err, KeysError::KeyFileCorrupt);
    }

    /// keys_test.zig:114 - truncated secret = corruption, NOT regeneration.
    #[test]
    fn keys_truncated_secret_is_corruption_not_regen() {
        let (_d, dir) = tmpdir();
        load_or_generate(&dir).unwrap();
        let secret_path = dir.join("secret.key");
        fs::write(&secret_path, b"short").unwrap();
        assert_eq!(
            load_or_generate(&dir).unwrap_err(),
            KeysError::KeyFileCorrupt
        );
    }

    /// keys_test.zig:132 - cert verbatim; ABSENT = len 0, never an error.
    #[test]
    fn keys_cert_absent_is_unbound_accept() {
        let (_d, dir) = tmpdir();
        let k = load_or_generate(&dir).unwrap();
        assert!(k.cert.is_empty());
        // verbatim load up to MAX_CERT
        let blob: Vec<u8> = (0..MAX_CERT).map(|i| (i % 251) as u8).collect();
        fs::write(dir.join("cert.bin"), &blob).unwrap();
        let k2 = load_or_generate(&dir).unwrap();
        assert_eq!(k2.cert, blob);
        // over-large cert = CertTooLarge, distinct fatal
        fs::write(dir.join("cert.bin"), vec![0u8; MAX_CERT + 1]).unwrap();
        assert_eq!(
            load_or_generate(&dir).unwrap_err(),
            KeysError::CertTooLarge
        );
    }

    /// keys_test.zig:152 - CA pubs in LABEL ORDER; missing ends the prefix.
    #[test]
    fn keys_ca_pubs_load_in_label_order() {
        let (_d, dir) = tmpdir();
        let ca_dir = dir.join("ca");
        fs::create_dir_all(&ca_dir).unwrap();
        for i in 0..3usize {
            fs::write(ca_dir.join(format!("ca{}.pub", i)), vec![i as u8; KEY_LEN]).unwrap();
        }
        let k = load_or_generate(&dir).unwrap();
        assert_eq!(k.ca_pubs.len(), 3);
        assert_eq!(k.ca_pubs[0], [0u8; KEY_LEN]);
        assert_eq!(k.ca_pubs[2], [2u8; KEY_LEN]);
    }

    /// keys_test.zig:182 + BE-RES-06 - stable lowercase hex over the pubkey,
    /// SAME value the resolver FP uses (single implementation, delegates).
    #[test]
    fn keys_fingerprint_matches_resolver_fp() {
        let pubkey = [7u8; KEY_LEN];
        let fp = fingerprint(&pubkey);
        assert_eq!(fp, crate::transport::resolver::executor_fp(&pubkey));
        let hex = std::str::from_utf8(&fp).unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    /// perms: secret files 0600, dir 0700.
    #[test]
    fn keys_permissions_0600_0700() {
        let (_d, dir) = tmpdir();
        load_or_generate(&dir).unwrap();
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("secret.key")), 0o600);
        assert_eq!(mode(&dir.join("sig.key")), 0o600);
    }
}
