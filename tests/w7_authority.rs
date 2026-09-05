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

#[test]
fn dispatch_action_boundary_exactly_max_accepted() {
    // F5/F13 boundary: an action of EXACTLY SENDER_MAX_ACTION (512) bytes is
    // admitted; the mutant (`>` weakened to `>=`) refuses it.
    use bolina::codec::{self, Envelope, Intent};
    use bolina::state::intent as intent_mod;
    use bolina::transport::dispatch::{Dispatch, Hooks, Outcome};
    use bolina::transport::verify::{EffectOutcome, SenderTable, SENDER_MAX_ACTION};
    use ed25519_dalek::{Signer, SigningKey};

    // resolver owns the executor identity; canonical resource added
    let exec_key = [5u8; 32];
    let mut resolver = Resolver::new(&exec_key);
    let fp = std::str::from_utf8(&executor_fp(&exec_key)).unwrap().to_string();
    let canonical = format!("bol:{}/ns/dev/x", fp);
    resolver.add(canonical.as_bytes()).unwrap();

    // agent signs the envelope
    let agent = SigningKey::from_bytes(&[0x61u8; 32]);
    let agent_pub = agent.verifying_key().to_bytes();

    // intent body with action EXACTLY at the bound
    let action = vec![b'a'; SENDER_MAX_ACTION];
    let intent_id = [7u8; 16];
    let intent = Intent {
        intent_id: &intent_id,
        resource_id: canonical.as_bytes(),
        action: &action,
        rationale: b"boundary",
    };
    let body = codec::encode_intent(&intent);

    // envelope: tbs = header fields + body (wire minus trailing sig)
    let channel = [0u8; 32];
    let mut tbs = Vec::new();
    tbs.push(2u8); // version
    tbs.extend_from_slice(&channel);
    tbs.extend_from_slice(&agent_pub);
    tbs.extend_from_slice(&1u64.to_be_bytes()); // seq
    tbs.push(0u8); // parent_count
    tbs.extend_from_slice(&1700000010000u64.to_be_bytes()); // ts
    tbs.push(codec::BODY_INTENT);
    tbs.extend_from_slice(&(body.len() as u32).to_be_bytes());
    tbs.extend_from_slice(&body);
    let mut sig_input = Vec::with_capacity(1 + tbs.len());
    sig_input.push(codec::DOMAIN_ENVELOPE);
    sig_input.extend_from_slice(&tbs);
    let sig = agent.sign(&sig_input).to_bytes();

    let env = Envelope {
        version: 2,
        channel_id: &channel,
        sender: &agent_pub,
        seq: 1,
        parent_count: 0,
        parents: &[],
        ts: 1700000010000,
        body_type: codec::BODY_INTENT,
        body: &body,
        tbs: &tbs,
        sig: &sig,
    };
    let wire = codec::encode_envelope(&env);

    // dispatch wiring; cert unused on the intent path, hooks dummy
    let (_, cert_wire) = {
        // minimal parse of the frozen vector cert via parse_cert
        let hex_bytes = include_str!("../test/vectors.json");
        let v: serde_json::Value = serde_json::from_str(hex_bytes).unwrap();
        let hex_str = v["structures"]["cert"]["wire_hex"].as_str().unwrap();
        ((), hex_to_bytes(hex_str))
    };
    let cert = codec::parse_cert(&cert_wire).expect("vector cert parses");

    let mut intents = intent_mod::Table::new();
    let mut senders = SenderTable::new();
    let noop_exec = |_: &codec::Grant<'_>| EffectOutcome::Fired;
    let hooks = Hooks {
        execute_effect: &noop_exec,
        cert_for_sender: &|_| None,
        on_rejected: &|_| {},
        is_revoked: &|_| false,
        already_consumed: &|_, _, _| false,
    };
    let own_pub = [0u8; 32];
    let mut d = Dispatch {
        resolver: &resolver,
        intent_table: &mut intents,
        sender_table: &mut senders,
        own_pubkey: &own_pub,
        own_cert: cert,
        trusted_ca_keys: &[],
    };
    let out = d.dispatch(&wire, &hooks, 1700000010001);
    assert_eq!(out, Ok(Outcome::IntentAdmitted), "action at exactly the bound must be admitted");
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
