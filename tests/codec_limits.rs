//! Limit tests — exercise exact boundary values to kill > vs >=/== mutants.

use bolina::codec::*;

// Helper: build a minimal valid envelope with body_len = given value
fn envelope_with_body_len(body_len: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(1); // version
    buf.extend_from_slice(&[0u8; 32]); // channel_id
    buf.extend_from_slice(&[0u8; 32]); // sender
    buf.extend_from_slice(&[0u8; 8]); // seq
    buf.push(0); // parent_count
    buf.extend_from_slice(&[0u8; 8]); // ts
    buf.push(BODY_INTENT); // body_type
    // body_len (4 bytes u32be)
    buf.push((body_len >> 24) as u8);
    buf.push((body_len >> 16) as u8);
    buf.push((body_len >> 8) as u8);
    buf.push((body_len) as u8);
    buf.extend_from_slice(&vec![0u8; body_len as usize]); // body
    buf.extend_from_slice(&[0u8; 64]); // sig
    buf
}

#[test]
fn envelope_body_at_exact_max_passes() {
    let buf = envelope_with_body_len(MAX_BODY);
    assert!(parse_envelope(&buf).is_ok());
}

#[test]
fn envelope_body_one_over_max_fails() {
    let buf = envelope_with_body_len(MAX_BODY + 1);
    assert!(parse_envelope(&buf).is_err());
}

fn envelope_with_parent_count(parent_count: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(1); // version
    buf.extend_from_slice(&[0u8; 32]); // channel_id
    buf.extend_from_slice(&[0u8; 32]); // sender
    buf.extend_from_slice(&[0u8; 8]); // seq
    buf.push(parent_count); // parent_count
    buf.extend_from_slice(&vec![0u8; parent_count as usize * LEN_PARENT]); // parents
    buf.extend_from_slice(&[0u8; 8]); // ts
    buf.push(BODY_INTENT); // body_type
    buf.extend_from_slice(&[0u8; 4]); // body_len = 0
    buf.extend_from_slice(&[0u8; 64]); // sig
    buf
}

#[test]
fn envelope_parent_count_at_max_passes() {
    let buf = envelope_with_parent_count(MAX_PARENTS);
    assert!(parse_envelope(&buf).is_ok());
}

#[test]
fn envelope_parent_count_over_max_fails() {
    let buf = envelope_with_parent_count(MAX_PARENTS + 1);
    assert!(parse_envelope(&buf).is_err());
}
