//! W6 CA boundary tests
use bolina::ca::{ca_init, ca_issue, ca_revoke, IssueReq};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("ca-{}-{}-{}", name, std::process::id(), n));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
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
    ca_init(&dir, 2).unwrap();
    assert!(dir.join("ca").exists());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_init_idempotent() {
    let dir = temp_dir("idempotent");
    ca_init(&dir, 2).unwrap();
    ca_init(&dir, 2).unwrap();
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_init_count_must_be_positive() {
    let dir = temp_dir("positive");
    assert!(ca_init(&dir, 0).is_err());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_init_count_max_boundary() {
    let dir = temp_dir("max");
    assert!(ca_init(&dir, 8).is_ok());
    let dir2 = temp_dir("over");
    assert!(ca_init(&dir2, 9).is_err());
    fs::remove_dir_all(&dir).ok();
    fs::remove_dir_all(&dir2).ok();
}

#[test]
fn ca_issue_requires_valid_role() {
    let dir = temp_dir("role");
    ca_init(&dir, 2).unwrap();
    let req = IssueReq {
        role: "invalid".into(),
        subject: "test".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    assert!(ca_issue(&dir, &req).is_err());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_issue_role_exact_match() {
    let dir = temp_dir("exact");
    ca_init(&dir, 2).unwrap();
    let req = IssueReq {
        role: "agentx".into(),
        subject: "test".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    assert!(ca_issue(&dir, &req).is_err());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_issue_ttl_positive() {
    let dir = temp_dir("ttl");
    ca_init(&dir, 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "test".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 0,
    };
    assert!(ca_issue(&dir, &req).is_err());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_issue_succeeds() {
    let dir = temp_dir("succeeds");
    ca_init(&dir, 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "agent-1".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    assert!(ca_issue(&dir, &req).is_ok());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_revoke_requires_valid_serial() {
    let dir = temp_dir("revoke");
    ca_init(&dir, 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "agent-1".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    let result = ca_issue(&dir, &req).unwrap();
    let serial = std::str::from_utf8(&result.serial_hex).unwrap();
    
    assert!(ca_revoke(&dir, "0000000000000000000000000000000000000000000000000000000000000000", None).is_err());
    assert!(ca_revoke(&dir, &serial, None).is_ok());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn ca_revoke_idempotent() {
    let dir = temp_dir("revoke-idem");
    ca_init(&dir, 2).unwrap();
    let req = IssueReq {
        role: "agent".into(),
        subject: "agent-1".into(),
        scopes: vec![scope("prod")],
        ttl_ms: 86400000,
    };
    let result = ca_issue(&dir, &req).unwrap();
    let serial = std::str::from_utf8(&result.serial_hex).unwrap();
    ca_revoke(&dir, &serial, None).unwrap();
    ca_revoke(&dir, &serial, None).unwrap();
    fs::remove_dir_all(&dir).ok();
}
