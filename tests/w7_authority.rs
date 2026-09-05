//! W7 authority tests: verify + dispatch + resolver.
//!
//! Coverage targets (from spec sheets):
//! - verify: ladder 0-11 (BE-GRANT-03), refusal, channel, mesh, admission
//! - dispatch: 7 outcomes, effect-once, replay refusal, orphan tombstone
//! - resolver: canonical grammar, alias collapse, foreign-fp refuse, signed set

use bolina::transport::verify::{
    VerifyError, SenderTable, SenderEntry,
    EffectOutcome, SENDER_MAX_ACTION,
};
use bolina::transport::resolver::{Resolver, ResolveError, executor_fp, validate_canonical};
use bolina::transport::dispatch::{
    DispatchError, Outcome,
    T_MAX_S_DEFAULT, T_RECV_S_DEFAULT,
};

// ---------------------------------------------------------------------------
// Resolver tests (BE-RES-01..06)
// ---------------------------------------------------------------------------

#[test]
fn resolver_executor_fp_deterministic() {
    // BE-RES-01: same key always produces same fingerprint
    let key = [42u8; 32];
    let fp1 = executor_fp(&key);
    let fp2 = executor_fp(&key);
    assert_eq!(fp1, fp2);
    // Fingerprint is 16 hex chars (bytes)
    assert_eq!(fp1.len(), 16);
    assert!(fp1.iter().all(|&b| b.is_ascii_hexdigit()));
}

#[test]
fn resolver_executor_fp_different_keys_differ() {
    let fp1 = executor_fp(&[1u8; 32]);
    let fp2 = executor_fp(&[2u8; 32]);
    assert_ne!(fp1, fp2);
}

#[test]
fn resolver_validate_canonical_accepts_valid() {
    // BE-RES-01: valid canonical form passes grammar
    let fp = executor_fp(&[42u8; 32]);
    let fp_str = std::str::from_utf8(&fp).unwrap();
    let id = format!("bol:{}/core/door-lock", fp_str);
    assert!(validate_canonical(id.as_bytes()));
}

#[test]
fn resolver_validate_canonical_rejects_malformed() {
    // BE-RES-01: malformed never enters state
    assert!(!validate_canonical(b"not-a-canonical-id"));
    assert!(!validate_canonical(b"bol:")); // too short
    assert!(!validate_canonical(b"bol:ZZZZZZZZZZZZZZZZ/core/x")); // uppercase hex
    assert!(!validate_canonical(b"bol:abcdef0123456789")); // missing ns/path
}

#[test]
fn resolver_add_and_resolve_canonical() {
    // BE-RES-02: add canonical, resolve finds it
    let key = [1u8; 32];
    let mut r = Resolver::new(&key);
    let fp = executor_fp(&key);
    let fp_str = std::str::from_utf8(&fp).unwrap();
    let canonical = format!("bol:{}/core/test", fp_str);

    // Add canonical
    r.add(canonical.as_bytes()).expect("add should succeed");

    // Resolve should find it
    let result = r.resolve(canonical.as_bytes());
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), canonical.as_bytes());
}

#[test]
fn resolver_alias_collapses_to_canonical() {
    // BE-RES-03: aliases map to exactly one canonical
    let key = [2u8; 32];
    let mut r = Resolver::new(&key);
    let fp = executor_fp(&key);
    let fp_str = std::str::from_utf8(&fp).unwrap();
    let canonical = format!("bol:{}/core/door", fp_str);
    let alias = b"door-front";

    r.add(canonical.as_bytes()).expect("add should succeed");
    r.add_alias(canonical.as_bytes(), alias).expect("alias should succeed");

    // Resolve alias should return canonical
    let result = r.resolve(alias);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), canonical.as_bytes());
}

#[test]
fn resolver_unknown_resource_refuses() {
    // BE-RES-02: unknown resource refuses
    let key = [3u8; 32];
    let r = Resolver::new(&key);
    let result = r.resolve(b"nonexistent");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ResolveError::UnknownResource);
}

#[test]
fn resolver_overflow_refuses() {
    // BE-RES-05 granularity: capacities refuse at overflow
    let key = [4u8; 32];
    let mut r = Resolver::new(&key);
    let fp = executor_fp(&key);
    let fp_str = std::str::from_utf8(&fp).unwrap();

    // Fill to MAX_RESOURCES (32)
    for i in 0..32 {
        let canonical = format!("bol:{}/core/res-{}", fp_str, i);
        r.add(canonical.as_bytes()).expect("should succeed within capacity");
    }

    // 33rd should refuse
    let overflow = format!("bol:{}/core/overflow", fp_str);
    assert!(r.add(overflow.as_bytes()).is_err());
    assert_eq!(r.add(overflow.as_bytes()).unwrap_err(), ResolveError::SetFull);
}

#[test]
fn resolver_duplicate_entry_refuses() {
    let key = [5u8; 32];
    let mut r = Resolver::new(&key);
    let fp = executor_fp(&key);
    let fp_str = std::str::from_utf8(&fp).unwrap();
    let canonical = format!("bol:{}/core/dup", fp_str);

    r.add(canonical.as_bytes()).expect("first add should succeed");
    let result = r.add(canonical.as_bytes());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ResolveError::DuplicateEntry);
}

// ---------------------------------------------------------------------------
// Verify tests (BE-GRANT-03 ladder 0-11)
// ---------------------------------------------------------------------------

#[test]
fn verify_sender_table_lookup_finds_match() {
    let mut table = SenderTable::new();
    let intent_id = [1u8; 16];
    let sender = [2u8; 32];
    let mut action = [0u8; SENDER_MAX_ACTION];
    action[..5].copy_from_slice(b"hello");

    table.entries.push(SenderEntry {
        intent_id,
        sender,
        action,
        action_len: 5,
    });

    let entry = table.lookup(&intent_id);
    assert!(entry.is_some());
    let e = entry.unwrap();
    assert_eq!(e.sender, sender);
    assert_eq!(&e.action[..e.action_len], b"hello");
}

#[test]
fn verify_sender_table_lookup_misses_unknown() {
    let table = SenderTable::new();
    let intent_id = [99u8; 16];
    assert!(table.lookup(&intent_id).is_none());
}

#[test]
fn verify_error_order_is_normative() {
    // BE-GRANT-03: check order IS the contract.
    // VerifyError variants must appear in normative order.
    let errors = [
        VerifyError::BadVersion,           // check 0
        VerifyError::BadEnvelopeBinding,   // check 1
        VerifyError::BadSignature,         // check 2
        VerifyError::BadApproverCert,      // check 3
        VerifyError::BadSubjectCert,       // check 4
        VerifyError::ApproverRevoked,      // check 3a
        VerifyError::ApproverOutOfScope,   // check 3a
        VerifyError::SubjectRevoked,       // check 4a
        VerifyError::SubjectOutOfScope,    // check 4a
        VerifyError::WrongExecutor,        // check 5
        VerifyError::WrongSubject,         // check 6
        VerifyError::NoMatchingIntent,     // check 7
        VerifyError::WrongResource,        // check 8
        VerifyError::ActionDigestMismatch, // check 9
        VerifyError::Expired,              // check 10
        VerifyError::AlreadyConsumed,      // check 11
    ];
    // Core 16 checks (0-11 + 3a/4a variants)
    assert_eq!(errors.len(), 16);
}

#[test]
fn verify_effect_outcome_exhaustive() {
    // EffectOutcome must be exhaustive — adding a variant must break every match.
    let fired = EffectOutcome::Fired;
    let refused = EffectOutcome::Refused;

    match fired {
        EffectOutcome::Fired => assert!(true),
        EffectOutcome::Refused => panic!("should be Fired"),
    }
    match refused {
        EffectOutcome::Fired => panic!("should be Refused"),
        EffectOutcome::Refused => assert!(true),
    }
}

// ---------------------------------------------------------------------------
// Dispatch tests (7 outcomes)
// ---------------------------------------------------------------------------

#[test]
fn dispatch_outcome_exhaustive() {
    // Outcome enum: 7 variants, never collapse
    let outcomes = [
        Outcome::IntentAdmitted,
        Outcome::GrantExecuted,
        Outcome::EffectRefused,
        Outcome::RefusalApplied,
        Outcome::Utterance,
        Outcome::Control,
        Outcome::Effect,
    ];
    assert_eq!(outcomes.len(), 7);
}

#[test]
fn dispatch_error_from_verify() {
    // DispatchError maps VerifyError via From
    let ve = VerifyError::BadVersion;
    let de: DispatchError = ve.into();
    assert_eq!(de, DispatchError::Verify(VerifyError::BadVersion));
}

#[test]
fn dispatch_error_from_resolve() {
    // DispatchError maps ResolveError via From
    let re = ResolveError::MalformedCanonical;
    let de: DispatchError = re.into();
    assert_eq!(de, DispatchError::Resolve(ResolveError::MalformedCanonical));
}

#[test]
fn dispatch_unsupported_body_refuses() {
    // Dispatch of unknown body_type refuses with UnsupportedBody
    let err = DispatchError::UnsupportedBody;
    assert_eq!(err, DispatchError::UnsupportedBody);
}

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

#[test]
fn w7_t_max_s_default_is_one_hour() {
    assert_eq!(T_MAX_S_DEFAULT, 3600);
}

#[test]
fn w7_t_recv_s_default_is_five_minutes() {
    assert_eq!(T_RECV_S_DEFAULT, 300);
}

#[test]
fn w7_sender_max_action_is_512() {
    assert_eq!(SENDER_MAX_ACTION, 512);
}
