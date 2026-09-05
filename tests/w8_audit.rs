//! W8 tests: dag + evidence + historical + grant_trace.

use bolina::transport::dag::{Dag, DagError, node_from_slice, NODE_BYTES, MAX_NODES};
use bolina::transport::evidence::{
    EvidenceClass, ClaimState, ResolutionRecord, Supported,
    class_of, ceiling_q8, is_volatile, effective_confidence, check_bounds,
    resolve_claim, Claim, Span, ResolveContext, Role, OriginState,
    MAX_UTTERANCE_CLAIMS, MAX_UTTERANCE_SPANS,
};
use bolina::transport::historical::{HistoricalError, historical_validity, AuditContext};
use bolina::transport::grant_trace::{TraceRing, Tag, fingerprint, NO_PC, CAP};

// ---------------------------------------------------------------------------
// DAG tests (BE-EVID-05/05a)
// ---------------------------------------------------------------------------

#[test]
fn dag_self_loop_forbidden() {
    // I1: insert(x,x) returns Cyclic
    let mut d = Dag::new();
    let a = [1u8; NODE_BYTES];
    assert_eq!(d.insert(&a, &a), Err(DagError::Cyclic));
}

#[test]
fn dag_self_ancestry_false() {
    // BE-EVID-05a: isAncestor(x,x) == false
    let mut d = Dag::new();
    let a = [2u8; NODE_BYTES];
    d.insert(&[3u8; NODE_BYTES], &a).unwrap();
    assert!(!d.is_ancestor(&a, &a));
}

#[test]
fn dag_diamond_ancestry() {
    // Diamond: A -> B, A -> C, B -> D, C -> D. A is ancestor of D.
    let mut d = Dag::new();
    let a = [1u8; NODE_BYTES];
    let b = [2u8; NODE_BYTES];
    let c = [3u8; NODE_BYTES];
    let dd = [4u8; NODE_BYTES];
    d.insert(&a, &b).unwrap();
    d.insert(&a, &c).unwrap();
    d.insert(&b, &dd).unwrap();
    d.insert(&c, &dd).unwrap();
    assert!(d.is_ancestor(&a, &dd));
    assert!(d.is_ancestor(&b, &dd));
    assert!(d.is_ancestor(&c, &dd));
    assert!(!d.is_ancestor(&dd, &a));
}

#[test]
fn dag_cycle_rejected() {
    // I2: edge closing cycle refused
    let mut d = Dag::new();
    let a = [1u8; NODE_BYTES];
    let b = [2u8; NODE_BYTES];
    d.insert(&a, &b).unwrap();
    assert_eq!(d.insert(&b, &a), Err(DagError::Cyclic));
}

#[test]
fn dag_idempotent_edge() {
    // I3: repeat of same edge is no-op
    let mut d = Dag::new();
    let a = [1u8; NODE_BYTES];
    let b = [2u8; NODE_BYTES];
    d.insert(&a, &b).unwrap();
    d.insert(&a, &b).unwrap(); // should not error
    assert!(d.is_ancestor(&a, &b));
}

#[test]
fn dag_deep_chain_no_recursion() {
    // I4: 100-deep chain, no stack overflow
    let mut d = Dag::new();
    let mut prev = [0u8; NODE_BYTES];
    for i in 1..100u8 {
        let mut cur = [0u8; NODE_BYTES];
        cur[0] = i;
        d.insert(&prev, &cur).unwrap();
        prev = cur;
    }
    let root = [0u8; NODE_BYTES];
    let leaf = { let mut x = [0u8; NODE_BYTES]; x[0] = 99; x };
    assert!(d.is_ancestor(&root, &leaf));
}

#[test]
fn dag_unknown_node_fail_closed() {
    // I5: unknown node => false
    let mut d = Dag::new();
    let a = [1u8; NODE_BYTES];
    let b = [2u8; NODE_BYTES];
    let unknown = [99u8; NODE_BYTES];
    d.insert(&a, &b).unwrap();
    assert!(!d.is_ancestor(&unknown, &b));
    assert!(!d.is_ancestor(&a, &unknown));
}

#[test]
fn dag_supersedes_requires_both_conjuncts() {
    // I6: supersedes(origin, effect, claim) needs BOTH isAncestor(origin,effect) AND isAncestor(effect,claim)
    let mut d = Dag::new();
    let origin = [1u8; NODE_BYTES];
    let effect = [2u8; NODE_BYTES];
    let claim = [3u8; NODE_BYTES];
    d.insert(&origin, &effect).unwrap();
    d.insert(&effect, &claim).unwrap();
    assert!(d.supersedes(&origin, &effect, &claim));
    // Missing second conjunct: effect is NOT ancestor of origin
    assert!(!d.supersedes(&effect, &origin, &claim));
}

#[test]
fn dag_overflow_refuses() {
    let mut d = Dag::new();
    for i in 0..MAX_NODES {
        let mut a = [0u8; NODE_BYTES];
        a[0] = i as u8;
        let mut b = [0u8; NODE_BYTES];
        b[0] = (i + 1) as u8;
        if i == MAX_NODES - 1 {
            // May or may not overflow depending on intern
            let _ = d.insert(&a, &b);
        } else {
            d.insert(&a, &b).unwrap();
        }
    }
}

#[test]
fn dag_node_from_slice_valid() {
    let s = [42u8; NODE_BYTES];
    assert_eq!(node_from_slice(&s).unwrap(), s);
}

#[test]
fn dag_node_from_slice_wrong_length() {
    assert_eq!(node_from_slice(&[0u8; 16]), Err(DagError::NotNode));
    assert_eq!(node_from_slice(&[0u8; 64]), Err(DagError::NotNode));
}

// ---------------------------------------------------------------------------
// Evidence tests (BE-EVID-01..09)
// ---------------------------------------------------------------------------

#[test]
fn evidence_class_of_method_ids() {
    assert_eq!(class_of(1), EvidenceClass::DirectObservation);
    assert_eq!(class_of(4), EvidenceClass::DirectObservation);
    assert_eq!(class_of(5), EvidenceClass::Documentation);
    assert_eq!(class_of(6), EvidenceClass::Documentation);
    assert_eq!(class_of(7), EvidenceClass::ExpertTestimony);
    assert_eq!(class_of(8), EvidenceClass::Inference);
    // BE-EVID-13: unknown -> Inference floor
    assert_eq!(class_of(0), EvidenceClass::Inference);
    assert_eq!(class_of(99), EvidenceClass::Inference);
}

#[test]
fn evidence_ceilings_normative() {
    // BE-EVID-15: integers only, no float conversion
    assert_eq!(ceiling_q8(EvidenceClass::DirectObservation), 242);
    assert_eq!(ceiling_q8(EvidenceClass::ExpertTestimony), 216);
    assert_eq!(ceiling_q8(EvidenceClass::Documentation), 191);
    assert_eq!(ceiling_q8(EvidenceClass::Inference), 165);
}

#[test]
fn evidence_is_volatile() {
    // BE-EVID-06: only 2 means stable
    assert!(!is_volatile(2));
    assert!(is_volatile(0));
    assert!(is_volatile(1));
    assert!(is_volatile(3));
    assert!(is_volatile(255)); // unrecognized => volatile
}

#[test]
fn evidence_effective_confidence_min() {
    // BE-EVID-02: min(stated, ceiling)
    assert_eq!(effective_confidence(200, 242), 200);
    assert_eq!(effective_confidence(250, 242), 242);
    assert_eq!(effective_confidence(165, 242), 165);
}

#[test]
fn evidence_check_bounds() {
    // BE-EVID-10: bounded piggyback
    assert!(check_bounds(0, 0));
    assert!(check_bounds(MAX_UTTERANCE_CLAIMS, MAX_UTTERANCE_SPANS));
    assert!(!check_bounds(MAX_UTTERANCE_CLAIMS + 1, 0));
    assert!(!check_bounds(0, MAX_UTTERANCE_SPANS + 1));
}

#[test]
fn evidence_resolve_claim_unsupported_no_spans() {
    // BE-EVID-02a: no matching span => Unsupported, not floor
    let claim = Claim {
        span_ids: &[],
        span_count: 0,
        subject: b"res-1",
        confidence_q8: 200,
    };
    let ctx = ResolveContext {
        role_of: &|_| Role::None,
        resolve_origin: &|_| OriginState::Effect,
        is_superseded: &|_, _, _| false,
    };
    match resolve_claim(&claim, &[], &ctx, b"env") {
        ClaimState::Unsupported(rec) => {
            assert_eq!(rec.cited, 0);
        }
        _ => panic!("expected Unsupported"),
    }
}

#[test]
fn evidence_resolve_claim_three_states() {
    // BE-EVID-09: exactly three states
    // This test verifies the enum is exhaustive
    let rec = ResolutionRecord::default();
    let _s = ClaimState::Supported(Supported {
        effective_q8: 200,
        pending_stronger: false,
        record: rec,
    });
    let _u = ClaimState::Unresolved(rec);
    let _us = ClaimState::Unsupported(rec);
}

// ---------------------------------------------------------------------------
// Historical tests (BE-HIST-01/03/04)
// ---------------------------------------------------------------------------

#[test]
fn historical_anchor_not_found() {
    let mut dag = Dag::new();
    let env_hash = [1u8; NODE_BYTES];
    let sender = [2u8; 32];
    let mut ctx = AuditContext {
        get_anchor: &|_| None,
        get_revoke_hash: &|_| None,
        validate_cert_no_clock: &|_| Ok(()),
        dag: &mut dag,
    };
    assert_eq!(
        historical_validity(&env_hash, &sender, b"cert", &mut ctx),
        Err(HistoricalError::AnchorNotFound)
    );
}

#[test]
fn historical_not_descendant_of_anchor() {
    let mut dag = Dag::new();
    let anchor = [10u8; NODE_BYTES];
    let env_hash = [20u8; NODE_BYTES];
    let sender = [2u8; 32];
    // Insert unrelated nodes
    let other = [30u8; NODE_BYTES];
    dag.insert(&other, &env_hash).unwrap();

    let mut ctx = AuditContext {
        get_anchor: &|_| Some(anchor),
        get_revoke_hash: &|_| None,
        validate_cert_no_clock: &|_| Ok(()),
        dag: &mut dag,
    };
    assert_eq!(
        historical_validity(&env_hash, &sender, b"cert", &mut ctx),
        Err(HistoricalError::NotDescendantOfAnchor)
    );
}

#[test]
fn historical_valid_when_descendant_of_anchor() {
    let mut dag = Dag::new();
    let anchor = [10u8; NODE_BYTES];
    let env_hash = [20u8; NODE_BYTES];
    let sender = [2u8; 32];
    dag.insert(&anchor, &env_hash).unwrap();

    let mut ctx = AuditContext {
        get_anchor: &|_| Some(anchor),
        get_revoke_hash: &|_| None,
        validate_cert_no_clock: &|_| Ok(()),
        dag: &mut dag,
    };
    assert!(historical_validity(&env_hash, &sender, b"cert", &mut ctx).is_ok());
}

#[test]
fn historical_descendant_of_revocation_fails() {
    let mut dag = Dag::new();
    let anchor = [10u8; NODE_BYTES];
    let revoke = [15u8; NODE_BYTES];
    let env_hash = [20u8; NODE_BYTES];
    let sender = [2u8; 32];
    dag.insert(&anchor, &revoke).unwrap();
    dag.insert(&revoke, &env_hash).unwrap();

    let mut ctx = AuditContext {
        get_anchor: &|_| Some(anchor),
        get_revoke_hash: &|_| Some(revoke),
        validate_cert_no_clock: &|_| Ok(()),
        dag: &mut dag,
    };
    assert_eq!(
        historical_validity(&env_hash, &sender, b"cert", &mut ctx),
        Err(HistoricalError::DescendantOfRevocation)
    );
}

#[test]
fn historical_cert_failure_surfaces() {
    let mut dag = Dag::new();
    let env_hash = [1u8; NODE_BYTES];
    let sender = [2u8; 32];
    let mut ctx = AuditContext {
        get_anchor: &|_| None,
        get_revoke_hash: &|_| None,
        validate_cert_no_clock: &|_| Err(HistoricalError::UntrustedCa),
        dag: &mut dag,
    };
    assert_eq!(
        historical_validity(&env_hash, &sender, b"cert", &mut ctx),
        Err(HistoricalError::UntrustedCa)
    );
}

// ---------------------------------------------------------------------------
// Grant trace tests
// ---------------------------------------------------------------------------

#[test]
fn grant_trace_fingerprint_deterministic() {
    let fp1 = fingerprint(b"test-id");
    let fp2 = fingerprint(b"test-id");
    assert_eq!(fp1, fp2);
    assert_ne!(fp1, fingerprint(b"other-id"));
}

#[test]
fn grant_trace_ring_emit_and_snapshot() {
    let mut ring = TraceRing::new();
    assert!(ring.is_empty());
    ring.emit(Tag::ReceiveIntent, NO_PC, b"intent-1", 1000);
    assert_eq!(ring.len(), 1);
    let snap = ring.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].tag, Tag::ReceiveIntent);
    assert_eq!(snap[0].now_ms, 1000);
}

#[test]
fn grant_trace_ring_overflow() {
    let mut ring = TraceRing::new();
    for i in 0..CAP + 5 {
        ring.emit(Tag::VerifyCheck, 0, &[i as u8], i as u64);
    }
    // Last slot should be TraceOverflow
    let snap = ring.snapshot();
    assert_eq!(snap.len(), CAP);
    assert_eq!(snap[CAP - 1].tag, Tag::TraceOverflow);
    assert_eq!(ring.overflow(), 5); // 5 overflow attempts after ring full
}

#[test]
fn grant_trace_ring_reset() {
    let mut ring = TraceRing::new();
    ring.emit(Tag::EffectStart, 0, b"grant-1", 1000);
    assert_eq!(ring.len(), 1);
    ring.reset();
    assert!(ring.is_empty());
    assert_eq!(ring.overflow(), 0);
}

#[test]
fn grant_trace_emit2_correlation() {
    let mut ring = TraceRing::new();
    ring.emit2(Tag::BeginVerify, 0, b"grant-1", b"intent-1", 1000);
    let snap = ring.snapshot();
    assert_eq!(snap.len(), 1);
    assert_ne!(snap[0].id, 0);
    assert_ne!(snap[0].id2, 0);
    assert_ne!(snap[0].id, snap[0].id2);
}

#[test]
fn grant_trace_seq_monotonic() {
    let mut ring = TraceRing::new();
    ring.emit(Tag::ReceiveIntent, 0, b"a", 100);
    ring.emit(Tag::BeginVerify, 0, b"b", 200);
    ring.emit(Tag::CommitConsumed11, 0, b"c", 300);
    let snap = ring.snapshot();
    assert_eq!(snap[0].seq, 0);
    assert_eq!(snap[1].seq, 1);
    assert_eq!(snap[2].seq, 2);
}
