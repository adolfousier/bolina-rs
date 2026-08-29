#![allow(unused_imports)]
//! W3: intent table + durable grant ledger (see specs/ sheets).

pub mod ffi;
pub mod intent;
pub mod ledger;

pub use intent::{Entry, IntentError, MAX_PENDING, MAX_RESOURCE, RefusalOutcome, State, Table, T_PENDING_MS, LEN_INTENT_ID};
pub use ledger::{
    GrantLedger, LedgerError, Recovery, GRANT_ID_LEN, MAX_LIVE,
    REC_COMMIT_LEN, REC_FIRST_RECEIPT_LEN, REC_PUBLISHED_LEN, REC_REVOKE_LEN, SIG_PUBKEY_LEN,
    TAG_COMMIT, TAG_FIRST_RECEIPT, TAG_PUBLISHED, TAG_REVOKE,
};
