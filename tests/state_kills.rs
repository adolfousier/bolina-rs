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
fn intent_timeout_at_exact_ms_must_expire() {
    // Mutant: now_ms > admitted_ms + T_PENDING_MS (exact ms not expired)
    // Kill: admit at t=0, expire at t=T_PENDING_MS exactly, verify it's expired
    let mut table = Table::new();
    let resource = [0u8; MAX_RESOURCE];
    let mut id = [0u8; LEN_INTENT_ID];
    id[0] = 1;
    table.admit(&id, &resource, 4, 0).unwrap();
    
    // At exactly T_PENDING_MS, the entry must be expired
    let expired = table.expire_timeouts(T_PENDING_MS);
    assert_eq!(expired, 1, "entry must be expired at exact T_PENDING_MS");
    assert_eq!(table.len(), 0, "table must be empty after expiry");
}
