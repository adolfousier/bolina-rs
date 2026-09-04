//! W6 CA boundary tests
use bolina::ca::{ca_init, ca_issue, ca_revoke, IssueReq};
use std::fs;

// G3 run-2 follow-up: TempDir auto-cleanup (tmpfs leak, same as state.rs).
fn temp_dir(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("ca-{name}-"))
        .tempdir()
        .unwrap()
}

fn scope(name: &str) -> [u8; 8] {
    let mut s = [0u8; 8];
    let bytes = name.as_bytes();
    s[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    s
}

#[test]
fn ca_init_creates_structure() {
    let dir = temp_dir("creates");
    ca_init(dir.path(), 2).unwrap();
    assert!(dir.path().join("ca").exists());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_init_idempotent() {
    let dir = temp_dir("idempotent");
    ca_init(dir.path(), 2).unwrap();
    ca_init(dir.path(), 2).unwrap();
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_init_count_must_be_positive() {
    let dir = temp_dir("positive");
    assert!(ca_init(dir.path(), 0).is_err());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_init_count_max_boundary() {
    let dir = temp_dir("max");
    assert!(ca_init(dir.path(), 8).is_ok());
    let dir2 = temp_dir("over");
    assert!(ca_init(dir2.path(), 9).is_err());
    fs::remove_dir_all(dir.path()).ok();
    fs::remove_dir_all(dir2.path()).ok();
}

#[test]
fn ca_issue_requires_valid_role() {
    let dir = temp_dir("role");
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "invalid".into(),
        subject: "test".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    assert!(ca_issue(dir.path(), &req).is_err());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_issue_role_exact_match() {
    let dir = temp_dir("exact");
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agentx".into(),
        subject: "test".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    assert!(ca_issue(dir.path(), &req).is_err());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_issue_ttl_positive() {
    let dir = temp_dir("ttl");
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "test".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 0,
    };
    assert!(ca_issue(dir.path(), &req).is_err());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_issue_succeeds() {
    let dir = temp_dir("succeeds");
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "agent-1".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    assert!(ca_issue(dir.path(), &req).is_ok());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_revoke_requires_valid_serial() {
    let dir = temp_dir("revoke");
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "agent-1".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    let result = ca_issue(dir.path(), &req).unwrap();
    let serial = std::str::from_utf8(&result.serial_hex).unwrap();
    
    assert!(ca_revoke(dir.path(), "0000000000000000000000000000000000000000000000000000000000000000", None).is_err());
    assert!(ca_revoke(dir.path(), &serial, None).is_ok());
    fs::remove_dir_all(dir.path()).ok();
}

#[test]
fn ca_revoke_idempotent() {
    let dir = temp_dir("revoke-idem");
    ca_init(dir.path(), 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "agent-1".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    let result = ca_issue(dir.path(), &req).unwrap();
    let serial = std::str::from_utf8(&result.serial_hex).unwrap();
    ca_revoke(dir.path(), &serial, None).unwrap();
    ca_revoke(dir.path(), &serial, None).unwrap();
    fs::remove_dir_all(dir.path()).ok();
}
