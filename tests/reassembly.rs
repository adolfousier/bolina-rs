//! W5 reassembly tests — port of reassembly_test.zig (8 tests)

use bolina::transport::reassembly::*;

type Reasm = PeerReassembler<4, 16>;

#[test]
fn be_tr_05_out_of_order_fragments_reassemble() {
    let mut r = Reasm::new();
    assert_eq!(r.ingest(1000, 1, 0, 3, 100), PeerEvent::Partial);
    assert_eq!(r.ingest(1000, 1, 2, 3, 100), PeerEvent::Partial);
    assert_eq!(r.ingest(1000, 1, 1, 3, 100), PeerEvent::Complete);
    assert_eq!(r.active_contexts(), 0);
}

#[test]
fn fragments_delivered_in_reverse_complete_on_last() {
    let mut r = Reasm::new();
    assert_eq!(r.ingest(1000, 1, 2, 3, 50), PeerEvent::Partial);
    assert_eq!(r.ingest(1000, 1, 1, 3, 50), PeerEvent::Partial);
    assert_eq!(r.ingest(1000, 1, 0, 3, 50), PeerEvent::Complete);
    assert_eq!(r.bytes_in_use(), 0);
}

#[test]
fn duplicate_fragment_counted_once_changes_nothing() {
    let mut r = Reasm::new();
    assert_eq!(r.ingest(1000, 1, 0, 3, 100), PeerEvent::Partial);
    assert_eq!(r.ingest(1000, 1, 0, 3, 100), PeerEvent::Duplicate);
    assert_eq!(r.ingest(1000, 1, 1, 3, 100), PeerEvent::Partial);
    assert_eq!(r.ingest(1000, 1, 2, 3, 100), PeerEvent::Complete);
}

#[test]
fn exceeding_context_limit_drops_new_message_not_session() {
    let mut r = Reasm::new();
    for i in 0..4 {
        assert_eq!(r.ingest(1000, i, 0, 2, 100), PeerEvent::Partial);
    }
    assert_eq!(r.active_contexts(), 4);
    // 5th message dropped
    assert_eq!(r.ingest(1000, 99, 0, 2, 100), PeerEvent::MessageDropped);
    assert_eq!(r.active_contexts(), 4);
}

#[test]
fn exceeding_memory_budget_drops_message_not_session() {
    // Test per-message limit (MAX_MESSAGE = 1 MiB)
    let mut r = Reasm::new();
    // Use 100 KB fragments; 10 of them = 1 MiB
    for i in 0..10 {
        assert_eq!(r.ingest(1000, 1, i, 12, 100_000), PeerEvent::Partial);
    }
    // 11th fragment exceeds MAX_MESSAGE
    assert_eq!(r.ingest(1000, 1, 10, 12, 100_000), PeerEvent::MessageDropped);
}

#[test]
fn incomplete_context_older_than_30s_evicted() {
    let mut r = Reasm::new();
    assert_eq!(r.ingest(1000, 1, 0, 3, 100), PeerEvent::Partial);
    assert_eq!(r.active_contexts(), 1);
    r.evict_expired(1000 + INCOMPLETE_TIMEOUT_MS);
    assert_eq!(r.active_contexts(), 0);
}

#[test]
fn node_capacity_admits_sessions_up_to_ceiling() {
    let mut nc = NodeCapacity::new();
    for _ in 0..SESSIONS_PER_NODE {
        assert_eq!(nc.try_admit_session(), NodeEvent::Admitted);
    }
    assert_eq!(nc.sessions(), SESSIONS_PER_NODE);
    assert_eq!(nc.try_admit_session(), NodeEvent::Refused);
    nc.release_session();
    assert_eq!(nc.sessions(), SESSIONS_PER_NODE - 1);
    assert_eq!(nc.try_admit_session(), NodeEvent::Admitted);
}

#[test]
fn node_capacity_memory_gate() {
    let mut nc = NodeCapacity::new();
    assert!(nc.within_memory(MEMORY_PER_NODE));
    nc.add_bytes(MEMORY_PER_NODE);
    assert!(!nc.within_memory(1));
    nc.release_bytes(MEMORY_PER_NODE);
    assert!(nc.within_memory(MEMORY_PER_NODE));
}

#[test]
fn exact_max_fragments_total_must_be_accepted() {
    // Code: total > MAX_FRAGMENTS is malformed; total == MAX_FRAGMENTS is legal.
    // Mutant >= would drop the boundary message.
    use bolina::transport::reassembly::{PeerReassembler, PeerEvent};
    let mut r: PeerReassembler<8, 64> = PeerReassembler::new();
    let ev = r.ingest(0, 1, 0, 64, 100);
    assert!(!matches!(ev, PeerEvent::MessageDropped),
        "total == MAX_FRAGMENTS (64) must be accepted, got {:?}", ev);
    // total == MAX_FRAGMENTS+1 must be dropped in both variants
    let ev = r.ingest(0, 2, 0, 65, 100);
    assert!(matches!(ev, PeerEvent::MessageDropped),
        "total == MAX_FRAGMENTS+1 must be dropped");
}
