// Tests that kill surgical state mutants
use bolina::state::intent::*;

#[test]
fn exact_max_pending_must_be_accepted() {
    // Zig: `if (self.len == MAX_PENDING) return error.TableFull` — table holds
    // EXACTLY MAX_PENDING; the (MAX_PENDING+1)th distinct intent is refused.
    // Two-byte id/resource encoding: ids must NOT wrap at 256 (u8 wrap = dup).
    let mut table = Table::new();
    for i in 0..MAX_PENDING {
        let mut id = [0u8; LEN_INTENT_ID];
        id[0] = (i % 256) as u8;
        id[1] = (i / 256) as u8;
        let mut resource = [0u8; MAX_RESOURCE];
        resource[0] = (i % 256) as u8;
        resource[1] = (i / 256) as u8;
        table.admit(&id, &resource, 4, 0).unwrap();
    }
    assert_eq!(table.len(), MAX_PENDING, "exactly MAX_PENDING intents must fit");

    // The (MAX_PENDING+1)th DISTINCT intent must be refused as TableFull
    // (kills `len() > MAX_PENDING` which would admit it, and catches u8-wrap
    // false-positives by using an id/resource no entry carries)
    let mut overflow_id = [0u8; LEN_INTENT_ID];
    overflow_id[0] = 0xAB;
    overflow_id[1] = 0xCD;
    let mut overflow_resource = [0u8; MAX_RESOURCE];
    overflow_resource[0] = 0xAB;
    overflow_resource[1] = 0xCD;
    let result = table.admit(&overflow_id, &overflow_resource, 4, 0);
    assert!(matches!(result, Err(IntentError::TableFull)),
        "MAX_PENDING+1 distinct intent must be TableFull, got {:?}", result);
}

#[test]
fn exact_timeout_boundary_must_not_expire() {
    // Code uses > (strictly greater), so at EXACTLY T_PENDING_MS the intent must NOT expire
    // Mutant >= would incorrectly expire here
    let mut t = Table::new();
    let now: u64 = 1_000_000;
    let id: [u8; LEN_INTENT_ID] = [1u8; LEN_INTENT_ID];
    let resource: [u8; MAX_RESOURCE] = [0u8; MAX_RESOURCE];
    t.admit(&id, &resource, 4, now).unwrap();
    let expired = t.expire_timeouts(now + T_PENDING_MS);
    assert_eq!(expired, 0, "intent must NOT expire at exactly T_PENDING_MS (strict >)");
    let expired = t.expire_timeouts(now + T_PENDING_MS + 1);
    assert_eq!(expired, 1, "intent must expire at T_PENDING_MS + 1");
}

#[test]
fn ledger_consumed_max_live_boundary() {
    // Mutant: consumed.len() > MAX_LIVE (accepts MAX_LIVE+1)
    // Kill: add MAX_LIVE grants, verify the (MAX_LIVE+1)th fails
    use bolina::state::ledger::{GrantLedger, MAX_LIVE, GRANT_ID_LEN};
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ledger.bin");
    let mut ledger = GrantLedger::open(&path).unwrap();

    for i in 0..MAX_LIVE {
        let mut id = [0u8; GRANT_ID_LEN];
        id[0] = (i % 256) as u8;
        id[1] = (i / 256) as u8;
        let result = ledger.commit_consumed(&id, 1000, 0);
        assert!(result.is_ok(), "grant {} must be accepted", i);
    }

    let mut overflow_id = [0u8; GRANT_ID_LEN];
    overflow_id[0] = 0xAB;
    overflow_id[1] = 0xCD;
    let result = ledger.commit_consumed(&overflow_id, 1000, 0);
    assert!(result.is_err(), "MAX_LIVE+1 must be rejected");
}
