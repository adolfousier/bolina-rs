//! W9 binding: certificate identity chain + session binding (binding.zig port).
//!
//! BE-ID-01..04: certificate validation against trust set + clock.
//! BE-TR-01: post-handshake session binding via Ed25519 sig over Noise h.

use crate::codec::{verify_signed, DOMAIN_CERT};

pub const DOMAIN_BINDING: u8 = 0x05;
pub const ROLE_AGENT: u8 = 1 << 1;
pub const ROLE_EXECUTOR: u8 = 1 << 2;
pub const ROLE_APPROVER: u8 = 1 << 3;
pub const MAX_PRIVILEGED_LIFETIME_MS: u64 = 2_592_000_000; // 30 days
pub const APPROVER_QUORUM: u8 = 2;
pub const LEN_OVERLAY_ADDR: usize = 16;
const OVERLAY_PREFIX: u8 = 0xfd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    MalformedKey,
    BadCaSignature,
    UntrustedCa,
    CertExpired,
    CertTooLongLived,
    RoleAgentApprover,
    RoleAgentExecutor,
    RoleApproverExecutor,
    ApproverNoQuorum,
    BadBindingSig,
    KexPubkeyMismatch,
}

/// CertChainError: structural checks only, no clock (BE-HIST-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertChainError {
    MalformedKey,
    BadCaSignature,
    UntrustedCa,
    CertTooLongLived,
    RoleAgentApprover,
    RoleAgentExecutor,
    RoleApproverExecutor,
    ApproverNoQuorum,
}

/// Parsed certificate view for validation.
pub struct CertView<'a> {
    pub sig_pubkey: &'a [u8],
    pub kex_pubkey: &'a [u8],
    pub role_bits: u8,
    pub not_before: u64,
    pub not_after: u64,
    pub tbs: &'a [u8],
    pub ca_sigs: &'a [u8], // packed (ca_key || ca_sig) pairs
    pub ca_sig_count: usize,
}

pub const LEN_CA_KEY: usize = 32;
pub const LEN_CA_SIG: usize = 64;

/// BE-ID-03: reject forbidden role pairings.
pub fn check_role_constraints(role_bits: u8) -> Result<(), CertChainError> {
    let agent = (role_bits & ROLE_AGENT) != 0;
    let approver = (role_bits & ROLE_APPROVER) != 0;
    let executor = (role_bits & ROLE_EXECUTOR) != 0;
    if agent && approver { return Err(CertChainError::RoleAgentApprover); }
    if agent && executor { return Err(CertChainError::RoleAgentExecutor); }
    if approver && executor { return Err(CertChainError::RoleApproverExecutor); }
    Ok(())
}

/// BE-ID-01: overlay_addr = 0xfd || BLAKE2s-256(sig_pubkey)[0..15]
pub fn derive_overlay_addr(sig_pubkey: &[u8]) -> [u8; LEN_OVERLAY_ADDR] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(sig_pubkey);
    let digest = hasher.finalize();
    let mut addr = [0u8; LEN_OVERLAY_ADDR];
    addr[0] = OVERLAY_PREFIX;
    addr[1..].copy_from_slice(&digest[..LEN_OVERLAY_ADDR - 1]);
    addr
}

fn in_trust_set(ca_key: &[u8], trusted: &[&[u8]]) -> bool {
    trusted.iter().any(|k| *k == ca_key)
}

/// BE-ID-02/03/04: validate cert chain (structural, no clock).
pub fn validate_cert_chain(cert: &CertView<'_>, trusted_ca_keys: &[&[u8]]) -> Result<(), CertChainError> {
    check_role_constraints(cert.role_bits)?;

    if (cert.role_bits & ROLE_APPROVER) != 0 && cert.ca_sig_count < APPROVER_QUORUM as usize {
        return Err(CertChainError::ApproverNoQuorum);
    }

    if (cert.role_bits & (ROLE_APPROVER | ROLE_EXECUTOR)) != 0
        && cert.not_after.saturating_sub(cert.not_before) > MAX_PRIVILEGED_LIFETIME_MS
    {
        return Err(CertChainError::CertTooLongLived);
    }

    let pair_len = LEN_CA_KEY + LEN_CA_SIG;
    for i in 0..cert.ca_sig_count {
        let off = i * pair_len;
        if off + pair_len > cert.ca_sigs.len() {
            return Err(CertChainError::BadCaSignature);
        }
        let ca_key = &cert.ca_sigs[off..off + LEN_CA_KEY];
        let ca_sig = &cert.ca_sigs[off + LEN_CA_KEY..off + pair_len];

        if !verify_signed(DOMAIN_CERT, cert.tbs, ca_sig, ca_key) {
            return Err(CertChainError::BadCaSignature);
        }
        if !in_trust_set(ca_key, trusted_ca_keys) {
            return Err(CertChainError::UntrustedCa);
        }
    }
    Ok(())
}

/// BE-HIST-01: no-clock validation (type system proves no clock check).
pub fn validate_cert_no_clock(cert: &CertView<'_>, trusted_ca_keys: &[&[u8]]) -> Result<(), CertChainError> {
    validate_cert_chain(cert, trusted_ca_keys)
}

/// BE-ID-02: full cert validation with clock.
pub fn validate_cert(cert: &CertView<'_>, trusted_ca_keys: &[&[u8]], now_ms: u64) -> Result<(), BindingError> {
    validate_cert_chain(cert, trusted_ca_keys).map_err(|e| match e {
        CertChainError::MalformedKey => BindingError::MalformedKey,
        CertChainError::BadCaSignature => BindingError::BadCaSignature,
        CertChainError::UntrustedCa => BindingError::UntrustedCa,
        CertChainError::CertTooLongLived => BindingError::CertTooLongLived,
        CertChainError::RoleAgentApprover => BindingError::RoleAgentApprover,
        CertChainError::RoleAgentExecutor => BindingError::RoleAgentExecutor,
        CertChainError::RoleApproverExecutor => BindingError::RoleApproverExecutor,
        CertChainError::ApproverNoQuorum => BindingError::ApproverNoQuorum,
    })?;

    if now_ms < cert.not_before || now_ms >= cert.not_after {
        return Err(BindingError::CertExpired);
    }
    Ok(())
}

/// BE-TR-01 + F1: bind authenticated session.
pub fn bind_session(
    cert: &CertView<'_>,
    binding_sig: &[u8],
    handshake_hash: &[u8],
    remote_kex_pubkey: &[u8],
    trusted_ca_keys: &[&[u8]],
    now_ms: u64,
) -> Result<(), BindingError> {
    validate_cert(cert, trusted_ca_keys, now_ms)?;

    // F1: cert kex_pubkey must equal remote static key from handshake
    if cert.kex_pubkey.len() != remote_kex_pubkey.len()
        || cert.kex_pubkey != remote_kex_pubkey
    {
        return Err(BindingError::KexPubkeyMismatch);
    }

    // BE-TR-01: binding sig over handshake hash
    if !verify_signed(DOMAIN_BINDING, handshake_hash, binding_sig, cert.sig_pubkey) {
        return Err(BindingError::BadBindingSig);
    }

    Ok(())
}
