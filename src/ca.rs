//! ca.rs — CA CLI (offline material issuance)
//!
//! Port of src/ca_material.zig (297 lines) + ca_cli.zig (187 lines).
//! Commands: init, issue, list, show, revoke.
//!
//! F15 heritage: version = 3 ALWAYS (v3-with-empty-scopes = deny-all D-085 R4).
//! BE-CTRL-03: revoke body carries SUBJECT expiry, never admin's.

use blake2::Blake2s256;
use blake2::Digest;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::Path;

const DOMAIN_CERT: u8 = 0x01;
const KEY_LEN: usize = 32;
const MAX_PRIVILEGED_LIFETIME_MS: u64 = 30 * 24 * 3600 * 1000; // 30 days

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaError {
    BadRole,
    BadTtl,
    BadCount,
    NoCaKeys,
    TtlOverCap,
    CertUnreadable,
    DataDirUnwritable,
}

pub type Result<T> = std::result::Result<T, CaError>;

// --- Serial computation ---

pub fn serial_of(tbs: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(tbs);
    let full = hasher.finalize();
    let mut half = [0u8; 16];
    half.copy_from_slice(&full[..16]);
    let mut hex = [0u8; 32];
    for (i, b) in half.iter().enumerate() {
        hex[i * 2] = b"0123456789abcdef"[(b >> 4) as usize];
        hex[i * 2 + 1] = b"0123456789abcdef"[(b & 0xf) as usize];
    }
    hex
}

// --- ca init ---

pub fn ca_init(dir: &Path, count: usize) -> Result<()> {
    if count == 0 || count > 8 {
        return Err(CaError::BadCount);
    }
    fs::create_dir_all(dir).map_err(|_| CaError::DataDirUnwritable)?;
    let ca_dir = dir.join("ca");
    fs::create_dir_all(&ca_dir).map_err(|_| CaError::DataDirUnwritable)?;

    for i in 0..count {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let sig_path = ca_dir.join(format!("ca{}.sig", i));
        let pub_path = ca_dir.join(format!("ca{}.pub", i));

        fs::write(&sig_path, signing_key.to_bytes()).map_err(|_| CaError::DataDirUnwritable)?;
        fs::write(&pub_path, verifying_key.to_bytes()).map_err(|_| CaError::DataDirUnwritable)?;

        // Set 0600 on private key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sig_path, fs::Permissions::from_mode(0o600)).ok();
        }
    }
    Ok(())
}

// --- ca issue ---

pub struct IssueReq {
    pub role: String,
    pub subject: String,
    pub scopes: Vec<[u8; 8]>,
    pub ttl_ms: u64,
}
#[derive(Debug, PartialEq)]

pub struct IssueResult {
    pub serial_hex: [u8; 32],
}

pub fn ca_issue(ca_dir: &Path, req: &IssueReq) -> Result<IssueResult> {
    // Validate role
    let role_byte = match req.role.as_str() {
        "agent" => 0x01,
        "executor" => 0x02,
        "approver" => 0x03,
        _ => return Err(CaError::BadRole),
    };

    // Validate TTL
    if role_byte == 0x03 || role_byte == 0x02 {
        if req.ttl_ms > MAX_PRIVILEGED_LIFETIME_MS {
            return Err(CaError::TtlOverCap);
        }
    }

    // Load CA keys (in ca/ subdirectory)
    let ca_keys_dir = ca_dir.join("ca");
    let mut ca_sigs = vec![];
    let mut ca_pubs = vec![];
    for i in 0..8 {
        let sig_path = ca_keys_dir.join(format!("ca{}.sig", i));
        let pub_path = ca_keys_dir.join(format!("ca{}.pub", i));
        if sig_path.exists() && pub_path.exists() {
            let sig_bytes = fs::read(&sig_path).map_err(|_| CaError::NoCaKeys)?;
            let pub_bytes = fs::read(&pub_path).map_err(|_| CaError::NoCaKeys)?;
            if sig_bytes.len() == KEY_LEN && pub_bytes.len() == KEY_LEN {
                let mut sig_arr = [0u8; KEY_LEN];
                let mut pub_arr = [0u8; KEY_LEN];
                sig_arr.copy_from_slice(&sig_bytes);
                pub_arr.copy_from_slice(&pub_bytes);
                ca_sigs.push(sig_arr);
                ca_pubs.push(pub_arr);
            }
        }
    }
    if ca_sigs.len() < 2 {
        return Err(CaError::NoCaKeys);
    }

    // Build cert tbs (version 3 ALWAYS — F15)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expiry_ms = now_ms + req.ttl_ms;

    let mut tbs = vec![];
    tbs.push(3); // version = 3 ALWAYS
    tbs.push(role_byte);
    tbs.extend_from_slice(&[0; 32]); // sig_pubkey placeholder
    tbs.extend_from_slice(&[0; 32]); // kex_pubkey placeholder
    tbs.extend_from_slice(&now_ms.to_be_bytes());
    tbs.extend_from_slice(&expiry_ms.to_be_bytes());
    // subject (name_len u16 + name)
    let subject_bytes = req.subject.as_bytes();
    tbs.extend_from_slice(&(subject_bytes.len() as u16).to_be_bytes());
    tbs.extend_from_slice(subject_bytes);
    // scopes (count u8 + 8 bytes each)
    tbs.push(req.scopes.len() as u8);
    for s in &req.scopes {
        tbs.extend_from_slice(s);
    }

    // Compute serial
    let serial_hex = serial_of(&tbs);

    // Sign with DOMAIN_CERT || tbs
    let mut sig_input = vec![DOMAIN_CERT];
    sig_input.extend_from_slice(&tbs);
    for sig_bytes in &ca_sigs {
        let signing_key = SigningKey::from_bytes(sig_bytes);
        let sig = signing_key.sign(&sig_input);
        tbs.extend_from_slice(&sig.to_bytes());
    }

    // Write cert.bin
    let issued_dir = ca_dir.join("issued");
    fs::create_dir_all(&issued_dir).map_err(|_| CaError::DataDirUnwritable)?;
    let serial_str = std::str::from_utf8(&serial_hex).unwrap();
    let cert_path = issued_dir.join(format!("{}.bin", serial_str));
    fs::write(&cert_path, &tbs).map_err(|_| CaError::DataDirUnwritable)?;

    Ok(IssueResult { serial_hex })
}

// --- ca list ---

pub fn ca_list(ca_dir: &Path) -> Result<Vec<String>> {
    let issued_dir = ca_dir.join("issued");
    if !issued_dir.exists() {
        return Ok(vec![]);
    }
    let mut serials = vec![];
    for entry in fs::read_dir(&issued_dir).map_err(|_| CaError::CertUnreadable)? {
        let entry = entry.map_err(|_| CaError::CertUnreadable)?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".bin") {
            serials.push(name.trim_end_matches(".bin").to_string());
        }
    }
    Ok(serials)
}

// --- ca show ---

pub fn ca_show(ca_dir: &Path, serial: &str) -> Result<Vec<u8>> {
    let cert_path = ca_dir.join("issued").join(format!("{}.bin", serial));
    fs::read(&cert_path).map_err(|_| CaError::CertUnreadable)
}

// --- ca revoke ---

pub fn ca_revoke(ca_dir: &Path, serial: &str, subject_expiry_ms: Option<u64>) -> Result<Vec<u8>> {
    let cert_bytes = ca_show(ca_dir, serial)?;
    // Build revoke envelope (type 7, action 2)
    let mut envelope = vec![];
    envelope.push(7); // type
    envelope.push(2); // action = revoke
    envelope.extend_from_slice(&cert_bytes[..32]); // subject pubkey (placeholder)
    if let Some(expiry) = subject_expiry_ms {
        envelope.extend_from_slice(&expiry.to_be_bytes());
    }
    Ok(envelope)
}
