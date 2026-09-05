//! W10 control_api integration tests - the 10 inherited from
//! control_api_test.zig (sheet specs/control_api.md).

use bolina::control_api::{
    get_intent_state, metrics_body, parse_since, post_intent, ApiError, EventRing, IntentOutcome,
    Metrics, BODY_MAX, ID_HEX_LEN, SUBJ_HEX_LEN,
};
use bolina::state::intent;
use bolina::transport::resolver::{executor_fp, Resolver};

fn hex64(b: u8) -> String {
    // 64 hex chars = 32 bytes: one byte's 2-char hex, repeated 32x
    format!("{:02x}", b).repeat(32)
}

fn setup() -> (Resolver, intent::Table, Metrics, EventRing) {
    let key = [5u8; 32];
    let mut r = Resolver::new(&key);
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());
    r.add(canonical.as_bytes()).expect("add canonical");
    (r, intent::Table::new(), Metrics { admitted_total: 0 }, EventRing::new())
}

fn body(id: &str, resource: &str, subject: &str) -> String {
    format!(
        "{{\"id\":\"{}\",\"resource\":\"{}\",\"action\":\"read\",\"rationale\":\"r\",\"subject\":\"{}\"}}",
        id, resource, subject
    )
}

/// 1. happy admit + counter bumped on THIS path only.
#[test]
fn ctrl_api_happy_admit_202_counter_one() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let id = hex64(0xab);
    let key = [5u8; 32];
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());
    let out = post_intent(&body(&id, &canonical, &hex64(0x11)), &mut r, &mut t, &mut m, &mut ring, 0);
    assert_eq!(out, Ok(IntentOutcome::Accepted));
    assert_eq!(m.admitted_total, 1);
    assert_eq!(ring.events.len(), 1);
}

/// 2. duplicate id idempotent 202; counter FROZEN at 1.
#[test]
fn ctrl_api_duplicate_id_202_idempotent_counter_frozen() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let id = hex64(0xcd);
    let key = [5u8; 32];
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());
    let b = body(&id, &canonical, &hex64(0x22));
    assert_eq!(post_intent(&b, &mut r, &mut t, &mut m, &mut ring, 0), Ok(IntentOutcome::Accepted));
    assert_eq!(
        post_intent(&b, &mut r, &mut t, &mut m, &mut ring, 1),
        Ok(IntentOutcome::AcceptedIdempotent)
    );
    assert_eq!(m.admitted_total, 1, "retry must NOT bump the counter");
    assert_eq!(ring.events.len(), 1, "no second publish");
}

/// 3. ResourceHeld => 409 (second intent, same resource, different id).
#[test]
fn ctrl_api_resource_held_409() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let key = [5u8; 32];
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());
    assert_eq!(
        post_intent(&body(&hex64(1), &canonical, &hex64(3)), &mut r, &mut t, &mut m, &mut ring, 0),
        Ok(IntentOutcome::Accepted)
    );
    let err = post_intent(&body(&hex64(2), &canonical, &hex64(3)), &mut r, &mut t, &mut m, &mut ring, 1);
    assert!(matches!(err, Err(ApiError::Intent(intent::IntentError::ResourceHeld))));
    assert_eq!(err.unwrap_err().status(), 409);
    assert_eq!(m.admitted_total, 1);
}

/// 4. unknown resource => 422.
#[test]
fn ctrl_api_unknown_resource_422() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let err = post_intent(&body(&hex64(9), "bol:unknown/ns/y", &hex64(4)), &mut r, &mut t, &mut m, &mut ring, 0);
    assert!(matches!(err, Err(ApiError::Resolve(_))));
    assert_eq!(err.unwrap_err().status(), 422);
}

/// 5. malformed set => 400 (bad id hex, bad subject, missing fields).
#[test]
fn ctrl_api_malformed_400_set() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let key = [5u8; 32];
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());
    // id wrong length
    assert_eq!(
        post_intent(&body("abcd", &canonical, &hex64(6)), &mut r, &mut t, &mut m, &mut ring, 0),
        Err(ApiError::BadRequest)
    );
    // subject wrong length (F16)
    let short_subj = "a".repeat(SUBJ_HEX_LEN - 1);
    assert_eq!(
        post_intent(&body(&hex64(7), &canonical, &short_subj), &mut r, &mut t, &mut m, &mut ring, 0),
        Err(ApiError::BadRequest)
    );
    // missing rationale
    let no_rat = format!(
        "{{\"id\":\"{}\",\"resource\":\"{}\",\"action\":\"read\",\"subject\":\"{}\"}}",
        hex64(8),
        canonical,
        hex64(9)
    );
    assert_eq!(
        post_intent(&no_rat, &mut r, &mut t, &mut m, &mut ring, 0),
        Err(ApiError::BadRequest)
    );
    assert_eq!(m.admitted_total, 0, "nothing admitted");
}

/// 6. intent state polling: pending visible via GET semantics.
#[test]
fn ctrl_api_get_intent_state_pending() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let key = [5u8; 32];
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());
    post_intent(&body(&hex64(2), &canonical, &hex64(5)), &mut r, &mut t, &mut m, &mut ring, 0).unwrap();
    let id_bytes = {
        let hex = hex64(2);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    };
    assert_eq!(get_intent_state(&id_bytes, &t), Ok("pending"));
    assert_eq!(get_intent_state(&[0u8; 32], &t), Err(ApiError::NotFound));
    assert_eq!(ApiError::NotFound.status(), 404);
}

/// 7. metrics counters verbatim with the control-plane trio from ARGS.
#[test]
fn ctrl_api_metrics_verbatim() {
    assert_eq!(
        metrics_body(2, 7, 1, 0),
        "bolina_intents_admitted_total 2\nbolina_ctl_requests_total 7\nbolina_ctl_auth_refused_total 1\nbolina_ctl_timeouts_total 0\n"
    );
}

/// 8. honest empty SSE at since=cursor (covered in ring tests); here the
/// parseSince strict-digits twin.
#[test]
fn ctrl_api_parse_since_strict() {
    assert!(parse_since("0").is_ok());
    assert!(parse_since("263").is_ok());
    assert!(parse_since("1x").is_err());
    assert!(parse_since("").is_err());
    assert_eq!(parse_since("1x").unwrap_err().status(), 400);
}

/// 9. ring seq-8 off-by-one (b4b94e7) - duplicated at the integration level.
#[test]
fn ctrl_api_ring_off_by_one_seq8() {
    let mut ring = EventRing::new();
    for _ in 0..(256 + 7) {
        ring.publish(bolina::control_api::EventTag::GrantExecuted);
    }
    assert_eq!(ring.events[0].0, 8);
}

/// 10. ID_HEX_LEN pinned at 64 (32 bytes hex).
#[test]
fn ctrl_api_id_hex_len_const() {
    assert_eq!(ID_HEX_LEN, 64);
    assert_eq!(SUBJ_HEX_LEN, 64);
}

/// BODY_MAX boundary: a body of EXACTLY BODY_MAX passes the gate (routed to
/// field validation), one byte over is 400 (mutant kill: `>` -> `>=`).
#[test]
fn ctrl_api_body_max_boundary_exact_ok_over_refused() {
    let (mut r, mut t, mut m, mut ring) = setup();
    let key = [5u8; 32];
    let canonical = format!("bol:{}/ns/dev/x", std::str::from_utf8(&executor_fp(&key)).unwrap());

    // exact-4096 body: pad the rationale so the total length is BODY_MAX
    let id = hex64(0x33);
    let base = body(&id, &canonical, &hex64(0x44));
    // the base's 1-char rationale gets REPLACED by the pad, hence +1
    let rationale_pad = " ".repeat(BODY_MAX - base.len() + 1);
    let padded = body_padded(&id, &canonical, &hex64(0x44), &rationale_pad);
    assert_eq!(padded.len(), BODY_MAX, "constructed body must be exactly BODY_MAX");
    let out = post_intent(&padded, &mut r, &mut t, &mut m, &mut ring, 0);
    assert_eq!(out, Ok(IntentOutcome::Accepted));

    // one byte over: 400
    let over = body_padded(&hex64(0x55), &canonical, &hex64(0x66), &rationale_pad);
    assert_eq!(over.len(), BODY_MAX + 1);
    assert_eq!(
        post_intent(&over, &mut r, &mut t, &mut m, &mut ring, 0),
        Err(ApiError::BadRequest)
    );
}

fn body_padded(id: &str, resource: &str, subject: &str, rationale: &str) -> String {
    format!(
        "{{\"id\":\"{}\",\"resource\":\"{}\",\"action\":\"read\",\"rationale\":\"{}\",\"subject\":\"{}\"}}",
        id, resource, rationale, subject
    )
}
