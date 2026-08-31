// Tests that kill surgical codec mutants — exact boundary values
// Uses PUBLIC API only (parse_envelope, encode_envelope, etc.)
use bolina::codec::*;

#[test]
fn exact_max_parents_must_be_accepted() {
    // Mutant: parent_count >= MAX_PARENTS (rejects exactly MAX_PARENTS)
    // Kill: build envelope with exactly 4 parents and verify parse_envelope accepts
    let mut buf = Vec::new();
    buf.push(0x01); // version
    buf.extend_from_slice(&[0u8; 32]); // channel_id
    buf.extend_from_slice(&[0u8; 32]); // sender
    buf.extend_from_slice(&0u64.to_be_bytes()); // seq
    buf.push(MAX_PARENTS); // parent_count = 4
    for i in 0..MAX_PARENTS {
        buf.extend_from_slice(&[i; 32]); // 4 parents
    }
    buf.extend_from_slice(&0u64.to_be_bytes()); // ts
    buf.push(0x02); // body_type
    buf.extend_from_slice(&10u32.to_be_bytes()); // body_len
    buf.extend_from_slice(&[0u8; 10]); // body
    buf.extend_from_slice(&[0u8; 64]); // sig (64 bytes)
    
    let parsed = parse_envelope(&buf);
    assert!(parsed.is_ok(), "envelope with exactly MAX_PARENTS parents must parse");
    assert_eq!(parsed.unwrap().parent_count, MAX_PARENTS);
}

#[test]
fn max_parents_plus_one_must_be_rejected() {
    // Mutant: parent_count >= MAX_PARENTS (accepts MAX_PARENTS+1)
    // Kill: build envelope with 5 parents and verify parse_envelope rejects
    let mut buf = Vec::new();
    buf.push(0x01); // version
    buf.extend_from_slice(&[0u8; 32]); // channel_id
    buf.extend_from_slice(&[0u8; 32]); // sender
    buf.extend_from_slice(&0u64.to_be_bytes()); // seq
    buf.push(MAX_PARENTS + 1); // parent_count = 5
    for i in 0..(MAX_PARENTS + 1) {
        buf.extend_from_slice(&[i; 32]); // 5 parents
    }
    buf.extend_from_slice(&0u64.to_be_bytes()); // ts
    buf.push(0x02); // body_type
    buf.extend_from_slice(&10u32.to_be_bytes()); // body_len
    buf.extend_from_slice(&[0u8; 10]); // body
    buf.extend_from_slice(&[0u8; 64]); // sig
    
    let parsed = parse_envelope(&buf);
    assert!(parsed.is_err(), "envelope with MAX_PARENTS+1 parents must be rejected");
}

#[test]
fn exact_max_body_must_be_accepted() {
    // Mutant: body_len >= MAX_BODY (rejects exactly MAX_BODY)
    // Kill: build envelope with body_len = MAX_BODY and verify parse_envelope accepts
    let body = vec![0u8; MAX_BODY as usize];
    let mut buf = Vec::new();
    buf.push(0x01); // version
    buf.extend_from_slice(&[0u8; 32]); // channel_id
    buf.extend_from_slice(&[0u8; 32]); // sender
    buf.extend_from_slice(&0u64.to_be_bytes()); // seq
    buf.push(0); // parent_count
    buf.extend_from_slice(&0u64.to_be_bytes()); // ts
    buf.push(0x02); // body_type
    buf.extend_from_slice(&MAX_BODY.to_be_bytes()); // body_len = MAX_BODY
    buf.extend_from_slice(&body); // body
    buf.extend_from_slice(&[0u8; 64]); // sig
    
    let parsed = parse_envelope(&buf);
    assert!(parsed.is_ok(), "envelope with exactly MAX_BODY must parse");
    assert_eq!(parsed.unwrap().body.len(), MAX_BODY as usize);
}

#[test]
fn domain_envelope_must_be_distinct() {
    // Mutant: DOMAIN_ENVELOPE wrong value (conflicts with DOMAIN_SPAN)
    // Kill: verify the constants are different
    assert_ne!(DOMAIN_ENVELOPE, DOMAIN_SPAN);
    assert_ne!(DOMAIN_ENVELOPE, DOMAIN_GRANT);
    assert_ne!(DOMAIN_ENVELOPE, DOMAIN_REFUSAL);
    assert_eq!(DOMAIN_ENVELOPE, 0x02); // exact value from SPEC
}

#[test]
fn max_parents_must_be_four() {
    // Mutant: MAX_PARENTS wrong constant (allows 5 instead of 4)
    // Kill: verify the constant is exactly 4
    assert_eq!(MAX_PARENTS, 4);
}

#[test]
fn max_ca_sigs_must_be_correct() {
    // Mutant: MAX_CA_SIGS wrong constant
    // Kill: verify the constant from SPEC
    assert_eq!(MAX_CA_SIGS, 4);
}

#[test]
fn envelope_roundtrip_preserves_parent_count() {
    // Kill cursor multiplication mutants
    // Build envelope with 3 parents, encode, parse, verify parent_count = 3
    let mut parents = Vec::new();
    for i in 0..3 {
        parents.extend_from_slice(&[i; 32]);
    }
    
    let e = Envelope {
        version: 0x01,
        channel_id: &[0u8; 32],
        sender: &[0u8; 32],
        seq: 0,
        parent_count: 3,
        parents: &parents,
        ts: 0,
        body_type: 0x02,
        body: &[0u8; 10],
        tbs: &[],
        sig: &[0u8; 64],
    };
    
    let wire = encode_envelope(&e);
    let parsed = parse_envelope(&wire).unwrap();
    assert_eq!(parsed.parent_count, 3);
    assert_eq!(parsed.parents.len(), 3 * 32);
}

#[test]
fn envelope_roundtrip_preserves_body_length() {
    // Kill cursor multiplication mutants
    // Build envelope with 100-byte body, encode, parse, verify body.len() = 100
    let body = vec![0x42u8; 100];
    let e = Envelope {
        version: 0x01,
        channel_id: &[0u8; 32],
        sender: &[0u8; 32],
        seq: 0,
        parent_count: 0,
        parents: &[],
        ts: 0,
        body_type: 0x02,
        body: &body,
        tbs: &[],
        sig: &[0u8; 64],
    };
    
    let wire = encode_envelope(&e);
    let parsed = parse_envelope(&wire).unwrap();
    assert_eq!(parsed.body.len(), 100);
}

#[test]
fn intent_roundtrip_preserves_fields() {
    // Kill cursor multiplication mutants
    // Build intent, encode, parse, verify all fields
    let i = Intent {
        intent_id: &[0x01; 16],
        resource_id: b"res",
        action: b"action",
        rationale: b"rationale",
    };
    
    let wire = encode_intent(&i);
    let parsed = parse_intent(&wire).unwrap();
    assert_eq!(parsed.intent_id, &[0x01; 16]);
    assert_eq!(parsed.resource_id, b"res");
    assert_eq!(parsed.action, b"action");
    assert_eq!(parsed.rationale, b"rationale");
}

#[test]
