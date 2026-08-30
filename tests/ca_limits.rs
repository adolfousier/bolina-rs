//! CA limit tests — kill mutants in ca_init/ca_issue/ca_revoke.

use bolina::ca::*;
use tempfile::TempDir;

#[test]
fn ca_init_with_zero_cas_fails() {
    let dir = TempDir::new().unwrap();
    let result = ca_init(dir.path(), 0);
    assert!(result.is_err());
}

#[test]
fn ca_init_with_one_ca_passes() {
    let dir = TempDir::new().unwrap();
    let result = ca_init(dir.path(), 1);
    assert!(result.is_ok());
}

#[test]
fn ca_init_with_max_cas_passes() {
    let dir = TempDir::new().unwrap();
    let result = ca_init(dir.path(), 8);  // MAX_CAS = 8
    assert!(result.is_ok());
}

#[test]
fn ca_init_over_max_cas_fails() {
    let dir = TempDir::new().unwrap();
    let result = ca_init(dir.path(), 9);  // MAX_CAS + 1
    assert!(result.is_err());
}

#[test]
fn ca_issue_with_zero_ttl_fails() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 1).unwrap();
    let req = IssueReq {
        role: "agent".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 0,
    };
    let result = ca_issue(dir.path(), &req);
    assert!(result.is_err());
}

#[test]
fn ca_issue_with_positive_ttl_passes() {
    let dir = TempDir::new().unwrap();
    ca_init(dir.path(), 1).unwrap();
    let req = IssueReq {
        role: "agent".to_string(),
        subject: "test".to_string(),
        scopes: vec![],
        ttl_ms: 3600000,
    };
    let result = ca_issue(dir.path(), &req);
    assert!(result.is_ok());
}
