// Tests that kill surgical state mutants
use bolina::state::intent::*;

#[test]
fn exact_max_pending_must_be_accepted() {
    // Mutant: entries.len() > MAX_PENDING (accepts MAX_PENDING+1)
    // Kill: fill exactly MAX_PENDING entries with DIFFERENT resources
    let mut table = Table::new();
    for i in 0..MAX_PENDING {
        let mut id = [0u8; LEN_INTENT_ID];
        id[0] = i as u8;
        let mut resource = [0u8; MAX_RESOURCE];
        resource[0] = i as u8; // different resource for each intent
        table.admit(&id, &resource, 4, 0).unwrap();
    }
    assert_eq!(table.len(), MAX_PENDING);
    
    // The MAX_PENDING+1 entry must be rejected (TableFull)
    let mut overflow_id = [0u8; LEN_INTENT_ID];
    overflow_id[0] = MAX_PENDING as u8;
    let mut overflow_resource = [0u8; MAX_RESOURCE];
    overflow_resource[0] = MAX_PENDING as u8;
    let result = table.admit(&overflow_id, &overflow_resource, 4, 0);
    assert!(result.is_err(), "MAX_PENDING+1 must be rejected");
}



#[test]
fn exact_timeout_boundary_must_not_expire() {
    // Code uses > (strictly greater), so at EXACTLY T_PENDING_MS the intent must NOT expire
    // Mutant >= would incorrectly expire here
    use bolina::state::intent::{Table, T_PENDING_MS, LEN_INTENT_ID, MAX_RESOURCE};
    let mut t = Table::new();
    let now: u64 = 1_000_000;
    let id: [u8; LEN_INTENT_ID] = [1u8; LEN_INTENT_ID];
    let resource: [u8; MAX_RESOURCE] = [0u8; MAX_RESOURCE];
    t.admit(&id, &resource, 4, now).unwrap();
    // At exactly now + T_PENDING_MS: must NOT expire (strict >)
    let expired = t.expire_timeouts(now + T_PENDING_MS);
    assert_eq!(expired, 0, "intent must NOT expire at exactly T_PENDING_MS (strict >)");
    // One ms later: must expire
    let expired = t.expire_timeouts(now + T_PENDING_MS + 1);
    assert_eq!(expired, 1, "intent must expire at T_PENDING_MS + 1");
}

#[test]
fn ledger_consumed_max_live_boundary() {
    // Mutant: consumed.len() > MAX_LIVE (accepts MAX_LIVE+1)
    // Kill: try to add MAX_LIVE+1 grants, verify the last one fails
    use bolina::state::ledger::{GrantLedger, MAX_LIVE, GRANT_ID_LEN};
    use std::fs;
    use tempfile::TempDir;
    
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ledger.bin");
    let mut ledger = GrantLedger::open(&path).unwrap();
    
    // Add exactly MAX_LIVE grants
    for i in 0..MAX_LIVE {
        let mut id = [0u8; GRANT_ID_LEN];
        id[0] = (i % 256) as u8;
        id[1] = (i / 256) as u8;
        let result = ledger.commit_consumed(&id, 1000, 0);
        assert!(result.is_ok(), "grant {} must be accepted", i);
    }
    
    // The MAX_LIVE+1 grant must fail (ResourceExhausted)
    let mut overflow_id = [0u8; GRANT_ID_LEN];
    overflow_id[0] = (MAX_LIVE % 256) as u8;
    overflow_id[1] = (MAX_LIVE / 256) as u8;
    let result = ledger.commit_consumed(&overflow_id, 1000, 0);
    assert!(result.is_err(), "MAX_LIVE+1 must be rejected");
}
