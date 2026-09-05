//! W10 tests: mac cookies + control API gaps.

use bolina::transport::mac1::{CookieSecret, MAC_BYTES, KEY_BYTES, COOKIE_ROTATE_MS};

// ---------------------------------------------------------------------------
// Mac cookies (BE-TR-04a)
// ---------------------------------------------------------------------------

#[test]
fn cookie_issue_and_verify() {
    let secret = CookieSecret::new([42u8; KEY_BYTES], 1000);
    let cookie = secret.issue_cookie(b"192.168.1.1:1234");
    assert!(secret.verify_cookie(b"192.168.1.1:1234", cookie));
}

#[test]
fn cookie_wrong_addr_fails() {
    let secret = CookieSecret::new([42u8; KEY_BYTES], 1000);
    let cookie = secret.issue_cookie(b"192.168.1.1:1234");
    assert!(!secret.verify_cookie(b"10.0.0.1:5678", cookie));
}

#[test]
fn cookie_different_secrets_differ() {
    let s1 = CookieSecret::new([1u8; KEY_BYTES], 0);
    let s2 = CookieSecret::new([2u8; KEY_BYTES], 0);
    let c1 = s1.issue_cookie(b"addr");
    let c2 = s2.issue_cookie(b"addr");
    assert_ne!(c1, c2);
}

#[test]
fn cookie_needs_rotate_false_when_fresh() {
    let secret = CookieSecret::new([0u8; KEY_BYTES], 1000);
    assert!(!secret.needs_rotate(1000));
    assert!(!secret.needs_rotate(1000 + COOKIE_ROTATE_MS - 1));
}

#[test]
fn cookie_needs_rotate_true_after_ttl() {
    let secret = CookieSecret::new([0u8; KEY_BYTES], 1000);
    assert!(secret.needs_rotate(1000 + COOKIE_ROTATE_MS));
    assert!(secret.needs_rotate(1000 + COOKIE_ROTATE_MS + 1));
}

#[test]
fn cookie_rotate_updates_secret_and_time() {
    let mut secret = CookieSecret::new([1u8; KEY_BYTES], 1000);
    let old_cookie = secret.issue_cookie(b"addr");

    secret.rotate([2u8; KEY_BYTES], 5000);
    assert!(!secret.needs_rotate(5000));
    assert_eq!(secret.created_ms, 5000);

    // New secret produces different cookies
    let new_cookie = secret.issue_cookie(b"addr");
    assert_ne!(old_cookie, new_cookie);
}

#[test]
fn cookie_deterministic_same_inputs() {
    let secret = CookieSecret::new([42u8; KEY_BYTES], 0);
    let c1 = secret.issue_cookie(b"same-addr");
    let c2 = secret.issue_cookie(b"same-addr");
    assert_eq!(c1, c2);
}

#[test]
fn cookie_length_is_16_bytes() {
    let secret = CookieSecret::new([0u8; KEY_BYTES], 0);
    let cookie = secret.issue_cookie(b"any");
    assert_eq!(cookie.len(), MAC_BYTES);
    assert_eq!(MAC_BYTES, 16);
}

#[test]
fn cookie_wrapping_sub_handles_clock_backwards() {
    // If now_ms < created_ms (clock went backwards), wrapping_sub gives a huge
    // number which is >= COOKIE_ROTATE_MS, so needs_rotate returns true.
    // This is the correct fail-closed behavior.
    let secret = CookieSecret::new([0u8; KEY_BYTES], 1000);
    assert!(secret.needs_rotate(500)); // clock went backwards -> rotate
}
