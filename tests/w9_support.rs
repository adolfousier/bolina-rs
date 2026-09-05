//! W9 tests: token + render + relay_store + replay + listener + binding.

use bolina::transport::token::{self, TOKEN_BYTES, TOKEN_HEX_LEN};
use bolina::transport::render::{self, RATIONALE_UNTRUSTED_LABEL, LEN_ACTION_DIGEST};
use bolina::transport::relay_store::{
    Store, StoreError, MAX_BODY, MAX_STORED, TTL_MS,
};
use bolina::transport::replay::{ReplayWindow, WINDOW_BITS};
use bolina::transport::listener::{EndpointRegistry, ListenError, MAX_ENDPOINTS};
use bolina::transport::binding::{
    self, CertView, BindingError, CertChainError,
    ROLE_AGENT, ROLE_EXECUTOR, ROLE_APPROVER,
    APPROVER_QUORUM, MAX_PRIVILEGED_LIFETIME_MS,
    check_role_constraints, derive_overlay_addr,
};

// ---------------------------------------------------------------------------
// Token tests
// ---------------------------------------------------------------------------

#[test]
fn token_generate_is_32_bytes() {
    let t = token::generate();
    assert_eq!(t.len(), TOKEN_BYTES);
}

#[test]
fn token_hex_round_trip() {
    let raw = [0xABu8; TOKEN_BYTES];
    let hex = token::hex(&raw);
    assert_eq!(hex.len(), TOKEN_HEX_LEN);
    // All lowercase hex
    assert!(hex.iter().all(|&b| b.is_ascii_hexdigit()));
    assert!(hex.iter().all(|&b| !b.is_ascii_uppercase()));
}

#[test]
fn token_verify_correct() {
    let raw = [42u8; TOKEN_BYTES];
    let hex = token::hex(&raw);
    assert!(token::verify(&hex, &hex));
}

#[test]
fn token_verify_wrong_length() {
    let hex = [0u8; TOKEN_HEX_LEN];
    assert!(!token::verify(b"too-short", &hex));
}

#[test]
fn token_verify_wrong_content() {
    let raw = [42u8; TOKEN_BYTES];
    let hex = token::hex(&raw);
    let mut wrong = hex;
    wrong[0] = b'X'; // corrupt first char
    assert!(!token::verify(&wrong, &hex));
}

// ---------------------------------------------------------------------------
// Render tests
// ---------------------------------------------------------------------------

#[test]
fn render_approval_digest_deterministic() {
    let view1 = render::render_approval(b"bol:abc/core/x", b"open", None);
    let view2 = render::render_approval(b"bol:abc/core/x", b"open", None);
    assert_eq!(view1.action_digest, view2.action_digest);
}

#[test]
fn render_approval_no_rationale() {
    let view = render::render_approval(b"res", b"act", None);
    assert!(view.rationale.is_none());
}

#[test]
fn render_approval_with_rationale_untrusted() {
    // BE-GRANT-07a: rationale always marked untrusted
    let view = render::render_approval(b"res", b"act", Some(b"some reason"));
    let rat = view.rationale.unwrap();
    assert_eq!(rat.untrusted_label, RATIONALE_UNTRUSTED_LABEL);
    assert_eq!(rat.text, b"some reason");
}

#[test]
fn render_approval_digest_is_blake2s() {
    let view = render::render_approval(b"res", b"action-data", None);
    assert_eq!(view.action_digest.len(), LEN_ACTION_DIGEST);
}

// ---------------------------------------------------------------------------
// Relay store tests (BE-MESH-03)
// ---------------------------------------------------------------------------

#[test]
fn relay_store_basic_store_and_drain() {
    let mut store = Store::new();
    let addr = [1u8; 16];
    store.store(addr, 0, b"hello", 1000).unwrap();
    assert_eq!(store.count, 1);
    let pkt = store.drain_next(&addr, 1000).unwrap();
    assert_eq!(pkt.body, b"hello");
    assert_eq!(pkt.sender_index, 0);
    assert_eq!(store.count, 0);
}

#[test]
fn relay_store_body_too_large() {
    let mut store = Store::new();
    let big = vec![0u8; MAX_BODY + 1];
    assert_eq!(store.store([1u8; 16], 0, &big, 0), Err(StoreError::BodyTooLarge));
}

#[test]
fn relay_store_ttl_expiry() {
    let mut store = Store::new();
    let addr = [2u8; 16];
    store.store(addr, 0, b"data", 1000).unwrap();
    // Before TTL: still there
    assert!(store.drain_next(&addr, 1000 + TTL_MS - 1).is_some());
    // Re-store since drain consumed it
    store.store(addr, 0, b"data2", 2000).unwrap();
    // After TTL: purged
    let purged = store.purge_expired(2000 + TTL_MS);
    assert!(purged > 0);
}

#[test]
fn relay_store_recipient_quota() {
    let mut store = Store::new();
    let addr = [3u8; 16];
    // Fill recipient to MAX_PER_RECIPIENT (64)
    for i in 0..64u32 {
        store.store(addr, i, &[i as u8; 4], 1000 + i as u64).unwrap();
    }
    // 65th should refuse
    assert_eq!(store.store(addr, 65, b"x", 2000), Err(StoreError::RecipientQuota));
    assert!(store.refused_quota > 0);
}

#[test]
fn relay_store_drain_fifo_order() {
    let mut store = Store::new();
    let addr = [4u8; 16];
    store.store(addr, 1, b"first", 1000).unwrap();
    store.store(addr, 2, b"second", 2000).unwrap();
    let pkt = store.drain_next(&addr, 2000).unwrap();
    assert_eq!(pkt.sender_index, 1); // oldest first
}

// ---------------------------------------------------------------------------
// Replay window tests (BE-TR-03)
// ---------------------------------------------------------------------------

#[test]
fn replay_first_counter_accepted() {
    let mut w = ReplayWindow::new();
    assert!(w.check(0)); // counter 0 is legal first counter
}

#[test]
fn replay_duplicate_rejected() {
    let mut w = ReplayWindow::new();
    assert!(w.check(5));
    assert!(!w.check(5)); // replay
}

#[test]
fn replay_in_order_sequence() {
    let mut w = ReplayWindow::new();
    for i in 0..100 {
        assert!(w.check(i));
    }
}

#[test]
fn replay_reordered_within_window() {
    let mut w = ReplayWindow::new();
    assert!(w.check(100));
    assert!(w.check(99));  // reorder within window
    assert!(w.check(50));  // still within window
}

#[test]
fn replay_below_window_rejected() {
    let mut w = ReplayWindow::new();
    assert!(w.check(2000));
    // 2000 - 1024 = 976; counter 975 is below window
    assert!(!w.check(2000 - WINDOW_BITS as u64));
}

#[test]
fn replay_advance_clears_old() {
    let mut w = ReplayWindow::new();
    assert!(w.check(0));
    assert!(w.check(1));
    // Jump far ahead
    assert!(w.check(10000));
    // Old counters are now below window
    assert!(!w.check(0));
    assert!(!w.check(1));
}

#[test]
fn replay_large_gap_accepted() {
    let mut w = ReplayWindow::new();
    assert!(w.check(0));
    assert!(w.check(100_000)); // big jump
}

// ---------------------------------------------------------------------------
// Listener / EndpointRegistry tests (BE-EXEC-02)
// ---------------------------------------------------------------------------

#[test]
fn listener_registry_claim_and_owns() {
    let mut reg = EndpointRegistry::new();
    let addr = [127u8, 0, 0, 1];
    reg.claim(&addr, 8080).unwrap();
    assert!(reg.owns(&addr, 8080));
    assert!(!reg.owns(&addr, 9090));
}

#[test]
fn listener_registry_double_claim_refuses() {
    // BE-EXEC-02: one listener per endpoint
    let mut reg = EndpointRegistry::new();
    let addr = [0u8, 0, 0, 0];
    reg.claim(&addr, 443).unwrap();
    assert_eq!(reg.claim(&addr, 443), Err(ListenError::EndpointBusy));
}

#[test]
fn listener_registry_release() {
    let mut reg = EndpointRegistry::new();
    let addr = [10u8, 0, 0, 1];
    reg.claim(&addr, 5000).unwrap();
    assert!(reg.owns(&addr, 5000));
    reg.release(&addr, 5000);
    assert!(!reg.owns(&addr, 5000));
}

#[test]
fn listener_registry_overflow_refuses() {
    let mut reg = EndpointRegistry::new();
    for i in 0..MAX_ENDPOINTS {
        let addr = [i as u8, 0, 0, 0];
        reg.claim(&addr, i as u16).unwrap();
    }
    assert_eq!(reg.claim(&[99u8, 0, 0, 0], 9999), Err(ListenError::EndpointBusy));
}

// ---------------------------------------------------------------------------
// Binding tests (BE-ID-01..04, BE-TR-01)
// ---------------------------------------------------------------------------

#[test]
fn binding_role_constraints_forbid_agent_approver() {
    // BE-ROLE-01: agent + approver forbidden
    assert_eq!(check_role_constraints(ROLE_AGENT | ROLE_APPROVER), Err(CertChainError::RoleAgentApprover));
}

#[test]
fn binding_role_constraints_forbid_agent_executor() {
    // BE-ROLE-02: agent + executor forbidden
    assert_eq!(check_role_constraints(ROLE_AGENT | ROLE_EXECUTOR), Err(CertChainError::RoleAgentExecutor));
}

#[test]
fn binding_role_constraints_forbid_approver_executor() {
    // BE-ROLE-04: approver + executor forbidden
    assert_eq!(check_role_constraints(ROLE_APPROVER | ROLE_EXECUTOR), Err(CertChainError::RoleApproverExecutor));
}

#[test]
fn binding_role_constraints_allow_single_roles() {
    assert!(check_role_constraints(ROLE_AGENT).is_ok());
    assert!(check_role_constraints(ROLE_EXECUTOR).is_ok());
    assert!(check_role_constraints(ROLE_APPROVER).is_ok());
}

#[test]
fn binding_overlay_addr_deterministic() {
    // BE-ID-01: overlay addr is commitment to key
    let key = [42u8; 32];
    let addr1 = derive_overlay_addr(&key);
    let addr2 = derive_overlay_addr(&key);
    assert_eq!(addr1, addr2);
    assert_eq!(addr1[0], 0xfd); // ULA prefix
    assert_eq!(addr1.len(), 16);
}

#[test]
fn binding_overlay_addr_different_keys_differ() {
    let addr1 = derive_overlay_addr(&[1u8; 32]);
    let addr2 = derive_overlay_addr(&[2u8; 32]);
    assert_ne!(addr1, addr2);
}

#[test]
fn binding_quorum_constant() {
    assert_eq!(APPROVER_QUORUM, 2);
}

#[test]
fn binding_max_lifetime_30_days() {
    assert_eq!(MAX_PRIVILEGED_LIFETIME_MS, 30 * 24 * 3600 * 1000);
}
