//! W2 conformance: the Rust codec against the FROZEN byte-a-byte vectors
//! (test/vectors.json, provenance in the Zig repo test/VECTORS-SOURCE.md).
//!
//! Same oracle the Zig vectors_test.zig and the Go wire package pass. Every
//! structure must: parse, re-encode BYTE-IDENTICAL, carry tbs == tbs_hex, and
//! verify its Ed25519 signature over domain_tag || tbs. Negatives must reject.
//!
//! serde_json is a DEV-dependency (test fixture parsing only — the Zig side
//! also consumed JSON test-only via std.json). Production src/ keeps exactly
//! the four crypto crates of D-096-A.

use blake2::Blake2s256;
use blake2::Digest;
use bolina::codec;
use serde::Deserialize;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[derive(Deserialize)]
struct Vectors {
    #[serde(rename = "structures")]
    structs: Structs,
    negatives: Vec<Negative>,
}

#[derive(Deserialize)]
struct Structs {
    cert: Structure,
    envelope_intent: Structure,
    span: Structure,
    grant: Structure,
    refusal: Structure,
    effect: Structure,
    claim: Structure,
}

#[derive(Deserialize)]
struct Structure {
    domain_tag: Option<String>,
    fields: Option<serde_json::Value>,
    tbs_hex: Option<String>,
    sig_input_hex: Option<String>,
    sig_hex: Option<String>,
    wire_hex: Option<String>,
    signer_pubkey: Option<String>,
    ca_sigs: Option<Vec<CaSig>>,
}

#[derive(Deserialize)]
struct CaSig {
    ca_key: String,
    sig: String,
}

#[derive(Deserialize)]
struct Negative {
    name: String,
    wire: String,
    expect: String,
}

fn vectors() -> &'static Vectors {
    use std::sync::OnceLock;
    static V: OnceLock<Vectors> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(include_str!("../test/vectors.json")).expect("vectors json"))
}

fn hex_byte(s: &str) -> u8 {
    u8::from_str_radix(s, 16).expect("tag hex")
}

#[test]
fn cert_parses_reencodes_and_both_ca_sigs_verify() {
    let c = &vectors().structs.cert;
    let wire = unhex(c.wire_hex.as_deref().unwrap());
    let cert = codec::parse_cert(&wire).expect("cert parses");
    assert_eq!(cert.tbs, unhex(c.tbs_hex.as_deref().unwrap()), "tbs byte-exact");
    assert_eq!(hex_byte(c.domain_tag.as_deref().unwrap()), codec::DOMAIN_CERT);
    assert_eq!(cert.version, 3, "F15 heritage: tool issues v3 always");
    // Both CA signatures verify over DOMAIN_CERT || tbs.
    let sigs = c.ca_sigs.as_ref().unwrap();
    assert_eq!(sigs.len(), cert.ca_sig_count as usize);
    for (i, ca) in sigs.iter().enumerate() {
        let off = i * (codec::LEN_CA_KEY + codec::LEN_SIG);
        let key = &cert.ca_sigs[off..off + codec::LEN_CA_KEY];
        assert_eq!(key, &unhex(&ca.ca_key)[..], "ca key in canonical order");
        assert!(
            codec::verify_signed(codec::DOMAIN_CERT, cert.tbs, &unhex(&ca.sig), &unhex(&ca.ca_key)),
            "ca sig {i} verifies"
        );
    }
    // Keys strictly ascending in the vector (canonical encoding).
    assert_eq!(codec::encode_cert(&cert), wire, "re-encode byte-identical");
}

#[test]
fn envelope_intent_parses_reencodes_sig_verifies_and_body_slices() {
    let v = vectors();
    let e = &v.structs.envelope_intent;
    let wire = unhex(e.wire_hex.as_deref().unwrap());
    let env = codec::parse_envelope(&wire).expect("envelope parses");
    assert_eq!(env.tbs, unhex(e.tbs_hex.as_deref().unwrap()), "tbs byte-exact");
    assert_eq!(hex_byte(e.domain_tag.as_deref().unwrap()), codec::DOMAIN_ENVELOPE);
    // BE-SIG-01 composition, vector-pinned: signature input = domain_tag || tbs.
    let mut sig_in = vec![hex_byte(e.domain_tag.as_deref().unwrap())];
    sig_in.extend_from_slice(&unhex(e.tbs_hex.as_deref().unwrap()));
    assert_eq!(sig_in, unhex(e.sig_input_hex.as_deref().unwrap()), "sig input = tag || tbs");
    let signer = unhex(e.signer_pubkey.as_deref().unwrap());
    assert!(
        codec::verify_signed(codec::DOMAIN_ENVELOPE, env.tbs, env.sig, &signer),
        "agent signature verifies"
    );
    // Body slices as Intent with the vector's semantic fields.
    let f = e.fields.as_ref().unwrap();
    let intent = codec::parse_intent(env.body).expect("body parses as intent");
    assert_eq!(intent.intent_id, unhex(f["body_intent_id"].as_str().unwrap()));
    assert_eq!(intent.resource_id, f["body_resource_id"].as_str().unwrap().as_bytes());
    assert_eq!(intent.action, f["body_action_utf8"].as_str().unwrap().as_bytes());
    assert_eq!(intent.rationale, f["body_rationale_utf8"].as_str().unwrap().as_bytes());
    assert_eq!(codec::encode_envelope(&env), wire, "re-encode byte-identical");
    assert_eq!(codec::encode_intent(&intent), env.body, "body re-encode byte-identical");
}

#[test]
fn grant_parses_reencodes_sig_verifies_and_action_digest_recomputes() {
    let g = &vectors().structs.grant;
    let wire = unhex(g.wire_hex.as_deref().unwrap());
    let gr = codec::parse_grant(&wire).expect("grant parses");
    assert_eq!(gr.tbs, unhex(g.tbs_hex.as_deref().unwrap()), "tbs byte-exact");
    assert_eq!(hex_byte(g.domain_tag.as_deref().unwrap()), codec::DOMAIN_GRANT);
    let signer = unhex(g.signer_pubkey.as_deref().unwrap());
    assert!(
        codec::verify_signed(codec::DOMAIN_GRANT, gr.tbs, gr.sig, &signer),
        "approver signature verifies"
    );
    // BE-GRANT-02: action_digest is BLAKE2s-256 of the Intent action, verifiable.
    let f = g.fields.as_ref().unwrap();
    let digest: [u8; 32] = Blake2s256::digest(f["action_utf8"].as_str().unwrap().as_bytes()).into();
    assert_eq!(gr.action_digest, &digest[..], "action digest recomputes");
    assert_eq!(gr.resource_id, f["resource_id"].as_str().unwrap().as_bytes());
    assert_eq!(gr.not_after, f["not_after"].as_u64().unwrap());
    assert_eq!(codec::encode_grant(&gr), wire, "re-encode byte-identical");
}

#[test]
fn refusal_parses_reencodes_sig_verifies_note_is_informational() {
    let r = &vectors().structs.refusal;
    let wire = unhex(r.wire_hex.as_deref().unwrap());
    let rf = codec::parse_refusal(&wire).expect("refusal parses");
    assert_eq!(rf.tbs, unhex(r.tbs_hex.as_deref().unwrap()), "tbs byte-exact");
    assert_eq!(hex_byte(r.domain_tag.as_deref().unwrap()), codec::DOMAIN_REFUSAL);
    let signer = unhex(r.signer_pubkey.as_deref().unwrap());
    assert!(
        codec::verify_signed(codec::DOMAIN_REFUSAL, rf.tbs, rf.sig, &signer),
        "refusal signature verifies"
    );
    let f = r.fields.as_ref().unwrap();
    assert_eq!(rf.note, f["note_utf8"].as_str().unwrap().as_bytes());
    assert_eq!(rf.intent_id, unhex(f["intent_id"].as_str().unwrap()));
    assert_eq!(codec::encode_refusal(&rf), wire, "re-encode byte-identical");
}

#[test]
fn span_parses_reencodes_sig_verifies_fields_pinned() {
    let s = &vectors().structs.span;
    let wire = unhex(s.wire_hex.as_deref().unwrap());
    let sp = codec::parse_span(&wire).expect("span parses");
    assert_eq!(sp.tbs, unhex(s.tbs_hex.as_deref().unwrap()), "tbs byte-exact");
    assert_eq!(hex_byte(s.domain_tag.as_deref().unwrap()), codec::DOMAIN_SPAN);
    let signer = unhex(s.signer_pubkey.as_deref().unwrap());
    assert!(
        codec::verify_signed(codec::DOMAIN_SPAN, sp.tbs, sp.sig, &signer),
        "executor signature verifies"
    );
    // Pinned by the Zig vectors_test.zig (:126-130).
    let f = s.fields.as_ref().unwrap();
    assert_eq!(sp.version, 2);
    assert_eq!(sp.method_id, 1, "1 -> DirectObservation (SPEC 7.4)");
    assert_eq!(sp.volatility, 2, "stable");
    assert_eq!(sp.observed_at, 1_700_000_030_000);
    assert_eq!(sp.span_id.len(), 16);
    assert_eq!(sp.span_id, unhex(f["span_id"].as_str().unwrap()));
    assert_eq!(sp.resource_id, f["resource_id"].as_str().unwrap().as_bytes());
    assert_eq!(codec::encode_span(&sp), wire, "re-encode byte-identical");
}

#[test]
fn effect_envelope_parses_and_verifies_under_envelope_domain() {
    let e = &vectors().structs.effect;
    let wire = unhex(e.wire_hex.as_deref().unwrap());
    let env = codec::parse_envelope(&wire).expect("effect envelope parses");
    assert_eq!(env.tbs, unhex(e.tbs_hex.as_deref().unwrap()), "tbs byte-exact");
    let signer = unhex(e.signer_pubkey.as_deref().unwrap());
    assert!(
        codec::verify_signed(codec::DOMAIN_ENVELOPE, env.tbs, env.sig, &signer),
        "effect signature verifies (same envelope domain, kind=effect)"
    );
}

#[test]
fn claim_body_wire_slices_text_subject_confidence_spans() {
    // Claim is a body with no own signature (authenticated via the Utterance
    // envelope). Wire (parser/channel.zig:315-342): u16 text_len || text ||
    // u16 subject_len || subject || u8 confidence_q8 || u8 span_count ||
    // span_count * 16B span_ids, no trailing slack.
    let c = &vectors().structs.claim;
    let wire = unhex(c.wire_hex.as_deref().unwrap());
    let mut pos = 2;
    let tlen = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    let text = &wire[pos..pos + tlen];
    pos += tlen;
    let slen = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
    pos += 2;
    let subject = &wire[pos..pos + slen];
    pos += slen;
    let confidence = wire[pos];
    pos += 1;
    let span_count = wire[pos] as usize;
    pos += 1;
    let span_ids = &wire[pos..pos + span_count * codec::LEN_SPAN_REF];
    pos += span_ids.len();
    let f = c.fields.as_ref().unwrap();
    assert_eq!(text, f["text"].as_str().unwrap().as_bytes());
    assert_eq!(subject, f["subject"].as_str().unwrap().as_bytes());
    assert_eq!(confidence, f["confidence_q8"].as_u64().unwrap() as u8, "confidence q8");
    assert_eq!(span_count, f["span_count"].as_u64().unwrap() as usize);
    assert_eq!(span_ids, unhex(f["span_ids_0"].as_str().unwrap()), "span id 0");
    assert_eq!(pos, wire.len(), "claim body total");
}

#[test]
fn every_negative_rejects() {
    for n in &vectors().negatives {
        let wire = unhex(&n.wire);
        match n.name.as_str() {
            // Input shorter than the fixed trailer: parse fails Truncated.
            "envelope_truncated_sig" => {
                assert_eq!(
                    codec::parse_envelope(&wire).err(),
                    Some(codec::ParseError::Truncated),
                    "negative {} must reject Truncated",
                    n.name
                );
            }
            // Unknown trailing bytes: parse fails TrailingBytes (SPEC 2.2).
            "envelope_trailing_byte" => {
                assert_eq!(
                    codec::parse_envelope(&wire).err(),
                    Some(codec::ParseError::TrailingBytes),
                    "negative {} must reject TrailingBytes",
                    n.name
                );
            }
            // Signature valid over tag 0x04 but the structure is an Envelope:
            // the PARSER accepts (structure is fine); the VERIFIER rejects.
            // BE-SIG-01 domain separation does its job.
            "envelope_wrong_domain_tag" => {
                let env = codec::parse_envelope(&wire).expect("structure parses");
                let signer = unhex(
                    vectors()
                        .structs
                        .envelope_intent
                        .signer_pubkey
                        .as_deref()
                        .unwrap(),
                );
                assert!(
                    !codec::verify_signed(codec::DOMAIN_ENVELOPE, env.tbs, env.sig, &signer),
                    "negative {} must fail verification under the envelope tag",
                    n.name
                );
            }
            other => panic!("unhandled negative vector: {other}"),
        }
    }
}
