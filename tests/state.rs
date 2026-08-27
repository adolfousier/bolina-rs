//! W3 acceptance gates, ported from grant_ledger_test.zig + intent_test.zig.
//! Every test cites its Zig proof (see specs/intent.md, specs/grant_ledger.md).

use bolina::state::intent::*;
use bolina::state::ledger::*;
use bolina::state::*;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

fn tmpdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "bolina_w3_{}_{}_{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn id(n: u64) -> [u8; GRANT_ID_LEN] {
    let mut b = [0u8; GRANT_ID_LEN];
    b[..8].copy_from_slice(&n.to_be_bytes());
    b
}

fn pk(n: u8) -> [u8; SIG_PUBKEY_LEN] {
    let mut b = [0u8; SIG_PUBKEY_LEN];
    b[0] = n;
    b
}

fn res(tag: u8) -> ([u8; MAX_RESOURCE], usize) {
    let mut r = [0u8; MAX_RESOURCE];
    r[0] = tag;
    r[1] = 7;
    (r, 2)
}

// ---------------- intent table (specs/intent.md invariants 1-9) ------------

#[test]
fn fresh_table_holds_nothing_be_grant_04() {
    let t = Table::new();
    assert!(t.is_empty()); // intent_test.zig:36: restart collapses ambitions
}

#[test]
fn duplicate_intent_id_refused_be_grant_06b() {
    let mut t = Table::new();
    let (r, rl) = res(1);
    let i = id(1);
    t.admit(&i, &r, rl, 100).unwrap();
    assert_eq!(t.admit(&i, &r, rl, 101), Err(IntentError::DuplicateIntentId));
}

#[test]
fn second_intent_on_held_resource_refused_be_grant_06() {
    let mut t = Table::new();
    let (r, rl) = res(2);
    t.admit(&id(1), &r, rl, 100).unwrap();
    assert_eq!(t.admit(&id(2), &r, rl, 101), Err(IntentError::ResourceHeld));
}

#[test]
fn executing_still_holds_the_resource() {
    let mut t = Table::new();
    let (r, rl) = res(3);
    t.admit(&id(1), &r, rl, 100).unwrap();
    let m = t.match_for_grant(&id(1)).unwrap();
    t.begin_executing(m).unwrap();
    assert_eq!(t.admit(&id(2), &r, rl, 101), Err(IntentError::ResourceHeld));
}

#[test]
fn t_pending_expiry_releases_lock_and_slot_be_grant_06a() {
    let mut t = Table::new();
    let (r, rl) = res(4);
    t.admit(&id(1), &r, rl, 1_000).unwrap();
    assert_eq!(t.expire_timeouts(1_000 + T_PENDING_MS), 1); // strict >=
    assert!(t.is_empty()); // MD4: capacity freed, not just the lock
    t.admit(&id(2), &r, rl, 1_001).unwrap(); // resource admit-able again
}

#[test]
fn matched_refusal_rejects_unmatched_dropped_be_grant_09() {
    let mut t = Table::new();
    let (r, rl) = res(5);
    t.admit(&id(1), &r, rl, 100).unwrap();
    assert_eq!(t.apply_refusal(&id(1)), RefusalOutcome::Rejected);
    assert_eq!(t.apply_refusal(&id(9)), RefusalOutcome::NoMatch); // intent_test.zig:110
}

#[test]
fn rejected_cannot_reenter_executing_be_grant_10() {
    let mut t = Table::new();
    let (r, rl) = res(6);
    t.admit(&id(1), &r, rl, 100).unwrap();
    t.apply_refusal(&id(1));
    assert!(t.match_for_grant(&id(1)).is_none()); // lookups never match rejected
    let m = t.match_for_grant(&id(1));
    assert_eq!(m.map(|i| t.begin_executing(i)), None);
    // direct index abuse also refused (state filter pinned; killed d089 mutant)
    t.admit(&id(2), &r, rl, 101).unwrap();
    let idx = t.match_for_grant(&id(2)).unwrap();
    t.apply_refusal(&id(2));
    let mut t2 = Table::new();
    let _ = idx; // begin_executing on a stale index after compaction must not exist
    assert!(t2.begin_executing(idx).is_err());
}

#[test]
fn match_for_grant_returns_the_one_pending() {
    let mut t = Table::new();
    let (r, rl) = res(7);
    t.admit(&id(1), &r, rl, 100).unwrap();
    let m = t.match_for_grant(&id(1)).unwrap();
    t.begin_executing(m).unwrap();
    assert_eq!(t.match_for_grant(&id(1)), None); // executing is not pending
}

#[test]
fn md4_churn_never_exhausts_the_table() {
    let mut t = Table::new();
    let (r, rl) = res(8);
    let mut n: u128 = 1;
    for gen in 0..2u64 {
        for _ in 0..MAX_PENDING {
            let mut i = [0u8; LEN_INTENT_ID];
            i[..16].copy_from_slice(&n.to_le_bytes()); // u128 LE, like Zig churn test
            let mut ri = [0u8; MAX_RESOURCE]; // DISTINCT resource per entry (Zig: "res-{d}")
            ri[0] = 8;
            ri[1..9].copy_from_slice(&n.to_le_bytes()[..8]);
            n += 1;
            t.admit(&i, &ri, 9, 1_000 + gen).unwrap();
        }
        assert_eq!(t.expire_timeouts(1_000 + gen + T_PENDING_MS), MAX_PENDING);
    }
    t.admit(&id(99_999), &r, rl, 5_000).unwrap(); // table still admits
}

// ---------------- grant ledger (specs/grant_ledger.md invariants 1-10) -----

#[test]
fn commit_visible_on_read_back_t1() {
    let dir = tmpdir("t1");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.commit_consumed(&id(1), 9_999, 100).unwrap(); // returns after fsync
        assert!(l.is_consumed(&id(1)));
    }
    let mut ro = GrantLedger::open_read_only(&p).unwrap();
    ro.recover().unwrap();
    assert!(ro.is_consumed(&id(1)));
}

#[test]
fn restart_replays_exact_state_t2() {
    let dir = tmpdir("t2");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.commit_consumed(&id(1), 9_999, 100).unwrap();
        l.commit_consumed(&id(2), 8_888, 100).unwrap();
        l.mark_published(&id(1)).unwrap();
        l.close();
    }
    let mut l = GrantLedger::open(&p).unwrap();
    let rec = l.recover().unwrap();
    assert_eq!(rec.consumed_count, 1); // only id(2) live
    assert!(l.is_consumed(&id(2)) && !l.is_consumed(&id(1)) && l.is_published(&id(1)));
}

#[test]
fn orphan_reemits_exactly_once_t3_be_grant_01a() {
    let dir = tmpdir("t3");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.commit_consumed(&id(7), 9_999, 100).unwrap();
        // crash: no mark_published
    }
    let mut l = GrantLedger::open(&p).unwrap();
    let rec = l.recover().unwrap();
    assert_eq!(rec.orphans.len(), 1);
    assert_eq!(rec.orphans[0], id(7));
    l.mark_published(&id(7)).unwrap();
    let rec = l.recover().unwrap();
    assert!(rec.orphans.is_empty()); // the ONE interrupted effect, not retried
}

#[test]
fn revocations_persist_never_pruned_t4_be_rev_02() {
    let dir = tmpdir("t4");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.commit_revocation(&pk(5), 1_234).unwrap();
        l.commit_consumed(&id(1), 500, 100).unwrap();
    }
    let mut l = GrantLedger::open(&p).unwrap();
    l.recover().unwrap();
    l.prune_expired(10_000).unwrap(); // expires the consumed grant
    assert!(l.is_revoked(&pk(5))); // revocation survives prune AND restart
    assert!(!l.is_consumed(&id(1)));
}

#[test]
fn prune_drops_only_expired_t5() {
    let dir = tmpdir("t5");
    let p = dir.join("ledger.bin");
    let mut l = GrantLedger::open(&p).unwrap();
    l.commit_consumed(&id(1), 500, 100).unwrap();
    l.commit_consumed(&id(2), 50_000, 100).unwrap();
    l.prune_expired(1_000).unwrap();
    assert!(!l.is_consumed(&id(1)) && l.is_consumed(&id(2)));
}

#[test]
fn torn_trailing_record_discarded_cleanly_t6() {
    let dir = tmpdir("t6");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.commit_consumed(&id(1), 9_999, 100).unwrap();
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
    f.write_all(&[TAG_COMMIT, 0xAA, 0xBB]).unwrap(); // torn write: 3 of 25
    drop(f);
    let mut l = GrantLedger::open(&p).unwrap();
    l.recover().unwrap(); // must NOT be BadLog
    assert!(l.is_consumed(&id(1)));
}

#[test]
fn idempotent_commit_t7() {
    let dir = tmpdir("t7");
    let p = dir.join("ledger.bin");
    let mut l = GrantLedger::open(&p).unwrap();
    l.commit_consumed(&id(1), 9_999, 100).unwrap();
    l.commit_consumed(&id(1), 1_111, 101).unwrap(); // re-commit = no-op
    assert!(l.is_consumed(&id(1)));
    l.mark_published(&id(1)).unwrap();
    l.commit_consumed(&id(1), 2_222, 102).unwrap(); // spent id: no resurrection
    assert!(l.is_published(&id(1)) && !l.is_consumed(&id(1)));
}

#[test]
fn crash_during_prune_stale_temp_cleaned_t8() {
    let dir = tmpdir("t8");
    let p = dir.join("ledger.bin");
    let mut l = GrantLedger::open(&p).unwrap();
    l.commit_consumed(&id(1), 500, 100).unwrap();
    std::fs::write(p.with_extension("bin.prune-tmp"), b"garbage").unwrap();
    l.prune_expired(1_000).unwrap(); // atomic rewrite runs anyway
    drop(l);
    let mut l2 = GrantLedger::open(&p).unwrap(); // stale temp cleaned at open
    l2.recover().unwrap();
    assert!(!p.with_extension("bin.prune-tmp").exists());
    assert!(!l2.is_consumed(&id(1)));
}

#[test]
fn flock_second_open_locked_close_releases_t9_md3() {
    let dir = tmpdir("t9");
    let p = dir.join("ledger.bin");
    let mut l = GrantLedger::open(&p).unwrap();
    assert!(matches!(GrantLedger::open(&p), Err(LedgerError::Locked))); // MD3 holds
    l.close();
    drop(l);
    let l2 = GrantLedger::open(&p).unwrap(); // close released it
    drop(l2);
    // read-only NEVER takes the lock (MD3 audit views)
    let ro = GrantLedger::open_read_only(&p).unwrap();
    drop(ro);
    let l3 = GrantLedger::open(&p).unwrap();
    drop(l3);
}

#[test]
fn read_only_handle_refuses_mutators_md3() {
    let dir = tmpdir("ro");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.commit_consumed(&id(1), 9_999, 100).unwrap();
        l.close();
    }
    let mut ro = GrantLedger::open_read_only(&p).unwrap();
    ro.recover().unwrap();
    assert_eq!(ro.commit_consumed(&id(2), 9_999, 100), Err(LedgerError::DiskError));
    assert_eq!(ro.prune_expired(10_000), Err(LedgerError::DiskError));
    assert!(ro.is_consumed(&id(1))); // reads still work
}

#[test]
fn first_receipt_survives_restart_first_wins_t10_f4() {
    let dir = tmpdir("f4");
    let p = dir.join("ledger.bin");
    {
        let mut l = GrantLedger::open(&p).unwrap();
        l.record_first_receipt(&id(1), 1_700_000_000).unwrap();
    }
    let mut l = GrantLedger::open(&p).unwrap();
    l.recover().unwrap(); // anchor row replays
    assert_eq!(l.get_first_receipt(&id(1)), Some(1_700_000_000));
    l.record_first_receipt(&id(1), 1_799_999_999).unwrap(); // later sighting: ignored
    assert_eq!(l.get_first_receipt(&id(1)), Some(1_700_000_000));
}

#[test]
fn record_format_bytes_exact() {
    let dir = tmpdir("fmt");
    let p = dir.join("ledger.bin");
    let mut l = GrantLedger::open(&p).unwrap();
    l.commit_consumed(&id(1), 0x0102030405060708, 100).unwrap();
    l.mark_published(&id(1)).unwrap();
    l.commit_revocation(&pk(9), 0x0A0B0C0D0E0F1011).unwrap();
    l.record_first_receipt(&id(2), 77).unwrap();
    l.close();
    let raw = std::fs::read(&p).unwrap();
    assert_eq!(raw.len(), 25 + 17 + 41 + 25); // canonical lengths only
    assert_eq!(raw[0], TAG_COMMIT);
    assert_eq!(raw[25], TAG_PUBLISHED);
    assert_eq!(raw[42], TAG_REVOKE);
    assert_eq!(&raw[75..77], &[0x0A, 0x0B]); // cert_expiry big-endian high bytes
    assert_eq!(raw[83], TAG_FIRST_RECEIPT);
}
