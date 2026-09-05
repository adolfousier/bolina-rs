//! W6 ca tests — port of ca_material_test.zig + ca_cli_test.zig

use bolina::ca::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn ca_init_creates_roots() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    assert!(dir.path().join("ca/ca0.sig").exists());
    assert!(dir.path().join("ca/ca0.pub").exists());
    assert!(dir.path().join("ca/ca1.sig").exists());
    assert!(dir.path().join("ca/ca1.pub").exists());
}

#[test]
fn ca_init_bad_count() {
    let dir = TempDir::new().unwrap();
    assert_eq!(ca_init(dir.path(), 0), Err(CaError::BadCount));
    assert_eq!(ca_init(dir.path(), 9), Err(CaError::BadCount));
}

#[test]
fn ca_issue_emits_v3_always() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".to_string(),
        subject: "test-agent".to_string(),
        scopes: vec![],
        ttl_ms: 3600_000,
    };
    let result = ca_issue(dir.path(), &req).unwrap();
    let serial_str = std::str::from_utf8(&result.serial_hex).unwrap();
    let cert_bytes = ca_show(dir.path(), serial_str).unwrap();
    assert_eq!(cert_bytes[0], 3); // version = 3 ALWAYS (F15)
}

// BE-ID-03: approver issuance enforces quorum and span cap;
// BE-REV-01: privileged TTL must not exceed 30-day cap.
#[test]
fn ca_issue_privileged_ttl_over_cap() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "approver".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 31 * 24 * 3600 * 1000, // 31 days > 30 day cap
    };
    assert_eq!(ca_issue(dir.path(), &req), Err(CaError::TtlOverCap));
}

#[test]
fn ca_issue_bad_role() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "unknown".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 3600_000,
    };
    assert_eq!(ca_issue(dir.path(), &req), Err(CaError::BadRole));
}

#[test]
fn ca_list_returns_serials() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "executor".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 3600_000,
    };
    ca_issue(dir.path(), &req).unwrap();
    let serials = ca_list(dir.path()).unwrap();
    assert_eq!(serials.len(), 1);
    assert_eq!(serials[0].len(), 32); // hex serial
}

#[test]
fn ca_show_reads_cert() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 3600_000,
    };
    let result = ca_issue(dir.path(), &req).unwrap();
    let serial_str = std::str::from_utf8(&result.serial_hex).unwrap();
    let cert_bytes = ca_show(dir.path(), serial_str).unwrap();
    assert!(cert_bytes.len() > 0);
}

// BE-CTRL-03: revocation envelope carries subject expiry (never admin's);
// BE-REV-01: 30-day cap enforced at issuance, revocation is the counterpart.
#[test]
fn ca_revoke_builds_envelope() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 3600_000,
    };
    let result = ca_issue(dir.path(), &req).unwrap();
    let serial_str = std::str::from_utf8(&result.serial_hex).unwrap();
    let envelope = ca_revoke(dir.path(), serial_str, Some(1000)).unwrap();
    assert_eq!(envelope[0], 7); // type
    assert_eq!(envelope[1], 2); // action = revoke
}
