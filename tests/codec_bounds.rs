//! Boundary-exact tests to kill cargo-mutants survivors.

use bolina::codec::*;

fn zero_pubkey() -> [u8; 32] { [0u8; 32] }
fn zero_sig() -> [u8; 64] { [0u8; 64] }

/// Kill mutant: `Cursor::u32be` pos += 4 → pos *= 4
#[test]
fn cursor_u32be_sequential_reads_independent() {
    let e = Envelope {
        version: 2, channel_id: &[0u8; LEN_CHANNEL_ID], sender: &zero_pubkey(),
        seq: 0xAABBCCDD_11223344, parents: &[], parent_count: 0,
        ts: 0, body_type: 0x02, body: &[0x42; 10], tbs: &[], sig: &zero_sig(),
    };
    let wire = encode_envelope(&e);
    let parsed = parse_envelope(&wire).unwrap();
    assert_eq!(parsed.seq, 0xAABBCCDD_11223344);
    assert_eq!(parsed.body.len(), 10);
    assert!(parsed.body.iter().all(|&b| b == 0x42));
}

/// Kill mutant: body_len > MAX_BODY → == or >=
#[test]
fn envelope_body_len_oversized() {
    let mut buf = Vec::new();
    buf.push(2);
    buf.extend_from_slice(&[0u8; LEN_CHANNEL_ID]);
    buf.extend_from_slice(&zero_pubkey());
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.push(0x02);
    buf.extend_from_slice(&(MAX_BODY + 1).to_be_bytes());
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&zero_sig());
    let result = parse_envelope(&buf);
    assert!(matches!(result, Err(ParseError::Oversize)), "body_len MAX_BODY+1 must fail, got {:?}", result);
}

/// Kill mutant: parent_count > MAX_PARENTS → == or >=
#[test]
fn envelope_parent_count_boundary() {
    let parents_buf = vec![0u8; MAX_PARENTS as usize * LEN_PARENT];
    let e = Envelope {
        version: 2, channel_id: &[0u8; LEN_CHANNEL_ID], sender: &zero_pubkey(),
        seq: 0, parents: &parents_buf, parent_count: MAX_PARENTS,
        ts: 0, body_type: 0x02, body: &[], tbs: &[], sig: &zero_sig(),
    };
    let wire = encode_envelope(&e);
    assert!(parse_envelope(&wire).is_ok(), "parent_count == MAX_PARENTS must succeed");
    let mut wire2 = wire.clone();
    wire2[73] = MAX_PARENTS + 1;
    let result = parse_envelope(&wire2);
    assert!(matches!(result, Err(ParseError::Oversize)), "parent_count MAX_PARENTS+1 must fail, got {:?}", result);
}

/// Build a valid cert wire buffer via encode_cert, then mutate boundary bytes.
fn build_valid_cert(scope_count: u8, ca_sig_count: u8) -> Vec<u8> {
    let mut ca_sigs = Vec::new();
    for i in 0..ca_sig_count {
        let mut key = [0u8; LEN_CA_KEY]; key[0] = (i + 1) as u8;
        ca_sigs.extend_from_slice(&key);
        ca_sigs.extend_from_slice(&zero_sig());
    }
    let scope_ids = vec![0u8; scope_count as usize * LEN_SCOPE_ID];
    let c = Cert {
        version: 3, role_bits: 0x04,
        sig_pubkey: &[1u8; 32], kex_pubkey: &[2u8; 32],
        not_before: 1000, not_after: 2000,
        name: b"test",
        scope_count, scope_ids: &scope_ids,
        ca_sig_count, ca_sigs: &ca_sigs,
        tbs: &[],
    };
    encode_cert(&c)
}

/// Kill mutant: scope_count > MAX_SCOPE → == or >=
#[test]
fn cert_scope_count_boundary() {
    let wire = build_valid_cert(MAX_SCOPE, 1);
    assert!(parse_cert(&wire).is_ok(), "scope_count == MAX_SCOPE must succeed, got {:?}", parse_cert(&wire));

    // Find scope_count byte offset: version(1) + role_bits(1) + sig_pub(32) + kex_pub(32) + not_before(8) + not_after(8) + name_len(2) + name(4) = 88
    let offset = 1 + 1 + 32 + 32 + 8 + 8 + 2 + 4;
    let mut wire2 = wire.clone();
    wire2[offset] = MAX_SCOPE + 1;
    let result = parse_cert(&wire2);
    assert!(matches!(result, Err(ParseError::Oversize)), "scope_count MAX_SCOPE+1 must fail Oversize, got {:?}", result);
}

/// Kill mutant: ca_sig_count > MAX_CA_SIGS → == or >=
#[test]
fn cert_ca_sig_count_boundary() {
    let wire = build_valid_cert(0, MAX_CA_SIGS);
    assert!(parse_cert(&wire).is_ok(), "ca_sig_count == MAX_CA_SIGS must succeed, got {:?}", parse_cert(&wire));

    // ca_sig_count offset: after scope_count(1) + scope_ids(0)
    let offset = 1 + 1 + 32 + 32 + 8 + 8 + 2 + 4 + 1;
    let mut wire2 = wire.clone();
    wire2[offset] = MAX_CA_SIGS + 1;
    let result = parse_cert(&wire2);
    assert!(matches!(result, Err(ParseError::Oversize)), "ca_sig_count MAX_CA_SIGS+1 must fail, got {:?}", result);
}

/// Kill mutant: ca_key <= prev_key → equal keys must fail
#[test]
fn cert_ca_keys_equal_fails() {
    let key = [5u8; LEN_CA_KEY];
    let mut ca_sigs = Vec::new();
    ca_sigs.extend_from_slice(&key); ca_sigs.extend_from_slice(&zero_sig());
    ca_sigs.extend_from_slice(&key); ca_sigs.extend_from_slice(&zero_sig()); // SAME key
    let c = Cert {
        version: 3, role_bits: 0x04,
        sig_pubkey: &[1u8; 32], kex_pubkey: &[2u8; 32],
        not_before: 1000, not_after: 2000,
        name: b"test", scope_count: 0, scope_ids: &[],
        ca_sig_count: 2, ca_sigs: &ca_sigs, tbs: &[],
    };
    let wire = encode_cert(&c);
    let result = parse_cert(&wire);
    assert!(matches!(result, Err(ParseError::Malformed)), "equal CA keys must fail, got {:?}", result);
}

/// Kill mutant: ca_key <= prev_key → descending must fail
#[test]
fn cert_ca_keys_descending_fails() {
    let mut key1 = [0u8; LEN_CA_KEY]; key1[0] = 10;
    let mut key2 = [0u8; LEN_CA_KEY]; key2[0] = 5;
    let mut ca_sigs = Vec::new();
    ca_sigs.extend_from_slice(&key1); ca_sigs.extend_from_slice(&zero_sig());
    ca_sigs.extend_from_slice(&key2); ca_sigs.extend_from_slice(&zero_sig());
    let c = Cert {
        version: 3, role_bits: 0x04,
        sig_pubkey: &[1u8; 32], kex_pubkey: &[2u8; 32],
        not_before: 1000, not_after: 2000,
        name: b"test", scope_count: 0, scope_ids: &[],
        ca_sig_count: 2, ca_sigs: &ca_sigs, tbs: &[],
    };
    let wire = encode_cert(&c);
    let result = parse_cert(&wire);
    assert!(matches!(result, Err(ParseError::Malformed)), "descending CA keys must fail, got {:?}", result);
}

/// Kill arithmetic mutants on limit constants
#[test]
fn limit_constants_are_correct() {
    assert_eq!(MAX_BODY, 1_048_064);
    assert_eq!(MAX_MESSAGE, 1 << 20);
    assert_eq!(MAX_ACTION, 262_144);
    assert_eq!(MAX_RATIONALE, 4_096);
}
