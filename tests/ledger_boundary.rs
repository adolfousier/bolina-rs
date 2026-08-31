//! Ledger MAX_LIVE boundary tests for mutation killing

use bolina::state::ledger::{GrantLedger, MAX_LIVE, GRANT_ID_LEN, SIG_PUBKEY_LEN};
use tempfile::TempDir;

fn make_unique_id(i: usize) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
    id
}

#[test]
fn ledger_consumed_max_live_boundary() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ledger.bin");
    let mut ledger = GrantLedger::open(&path).unwrap();
    
    // Adicionar MAX_LIVE grants com expiry muito futuro (não expiram)
    for i in 0..MAX_LIVE {
        let grant_id = make_unique_id(i);
        let expiry_ms = u64::MAX; // nunca expira
        let now_ms = 0;
        ledger.commit_consumed(&grant_id, expiry_ms, now_ms).unwrap();
    }
    
    // Tentar adicionar mais um (deve falhar se >= MAX_LIVE estiver correcto)
    let grant_id = make_unique_id(MAX_LIVE);
    let expiry_ms = u64::MAX;
    let now_ms = 0;
    assert!(ledger.commit_consumed(&grant_id, expiry_ms, now_ms).is_err());
}

#[test]
fn ledger_revoked_max_live_boundary() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ledger.bin");
    let mut ledger = GrantLedger::open(&path).unwrap();
    
    // Adicionar MAX_LIVE revogações
    for i in 0..MAX_LIVE {
        let sig_pubkey = make_unique_id(i);
        let cert_expiry_ms = u64::MAX;
        ledger.commit_revocation(&sig_pubkey, cert_expiry_ms).unwrap();
    }
    
    // Tentar adicionar mais uma (deve falhar se >= MAX_LIVE estiver correcto)
    let sig_pubkey = make_unique_id(MAX_LIVE);
    let cert_expiry_ms = u64::MAX;
    assert!(ledger.commit_revocation(&sig_pubkey, cert_expiry_ms).is_err());
}
