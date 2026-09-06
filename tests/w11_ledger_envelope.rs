//! Tests for the in-memory evidence ledger (ledger_envelope.rs).
//! Name-mandatory per ledger.md spec — each test pins a BE-* invariant.

use bolina::ledger_envelope::*;

fn hash(v: u8) -> [u8; HASH_BYTES] {
    [v; HASH_BYTES]
}
fn sender(v: u8) -> [u8; LEN_SIG_PUBKEY] {
    [v; LEN_SIG_PUBKEY]
}
fn channel(v: u8) -> [u8; LEN_CHANNEL_ID] {
    [v; LEN_CHANNEL_ID]
}

// --- BE-LEDGER-02: envelope stored by HASH not plaintext ---
#[test]
fn be_ledger_02_envelope_stored_by_hash() {
    let mut led = Ledger::new();
    let entry = EnvelopeEntry {
        hash: hash(0xAA),
        sender: sender(1),
        channel: channel(1),
        seq: 1,
    };
    led.insert_envelope(entry).unwrap();
    assert_eq!(led.envelope_count(), 1);
    // The store holds the hash, not the full envelope body.
    // (Structural: EnvelopeEntry stores hash + metadata, no body bytes.)
}

// --- BE-LEDGER-03: grant + effect envelopes recorded on acceptance ---
#[test]
fn be_ledger_03_grant_and_effect_recorded() {
    let mut led = Ledger::new();
    // Grant envelope
    led.insert_envelope(EnvelopeEntry {
        hash: hash(0x01),
        sender: sender(1),
        channel: channel(1),
        seq: 1,
    })
    .unwrap();
    // Effect envelope (different sender, same channel)
    led.insert_envelope(EnvelopeEntry {
        hash: hash(0x02),
        sender: sender(2),
        channel: channel(1),
        seq: 1,
    })
    .unwrap();
    assert_eq!(led.envelope_count(), 2);
}

// --- BE-LEDGER-01: unknown parents rejected ---
#[test]
fn be_ledger_01_unknown_parents_rejected() {
    let led = Ledger::new();
    let parents = [hash(0xFF)];
    assert!(!led.all_parents_present(&parents));
}

// --- BE-LEDGER-01: known parents pass ---
#[test]
fn be_ledger_01_known_parents_pass() {
    let mut led = Ledger::new();
    led.insert_envelope(EnvelopeEntry {
        hash: hash(0x10),
        sender: sender(1),
        channel: channel(1),
        seq: 1,
    })
    .unwrap();
    led.insert_envelope(EnvelopeEntry {
        hash: hash(0x20),
        sender: sender(2),
        channel: channel(1),
        seq: 1,
    })
    .unwrap();
    let parents = [hash(0x10), hash(0x20)];
    assert!(led.all_parents_present(&parents));
}

// --- BE-HIST-02: first envelope becomes anchor ---
#[test]
fn be_hist_02_first_envelope_becomes_anchor() {
    let mut led = Ledger::new();
    let pk = sender(1);
    let h = hash(0xAA);
    led.set_anchor(&pk, &h).unwrap();
    assert_eq!(led.get_anchor(&pk), Some(&h));
}

// --- Anchor idempotent twice OK ---
#[test]
fn anchor_idempotent_twice_ok() {
    let mut led = Ledger::new();
    let pk = sender(1);
    let h = hash(0xBB);
    led.set_anchor(&pk, &h).unwrap();
    led.set_anchor(&pk, &h).unwrap(); // idempotent
    assert_eq!(led.get_anchor(&pk), Some(&h));
}

// --- Anchor mismatched second call diverges ---
#[test]
fn anchor_mismatched_diverges() {
    let mut led = Ledger::new();
    let pk = sender(1);
    led.set_anchor(&pk, &hash(0xCC)).unwrap();
    let result = led.set_anchor(&pk, &hash(0xDD));
    assert_eq!(result, Err(LedgerError::Divergence));
}

// --- Second signer anchor retrievable past index zero ---
#[test]
fn second_signer_anchor_retrievable() {
    let mut led = Ledger::new();
    let pk1 = sender(1);
    let pk2 = sender(2);
    let h1 = hash(0x11);
    let h2 = hash(0x22);
    led.set_anchor(&pk1, &h1).unwrap();
    led.set_anchor(&pk2, &h2).unwrap();
    assert_eq!(led.get_anchor(&pk1), Some(&h1));
    assert_eq!(led.get_anchor(&pk2), Some(&h2));
}

// --- Revocation recorded immediately ---
#[test]
fn revocation_recorded_immediately() {
    let mut led = Ledger::new();
    let pk = sender(1);
    let rh = hash(0xEE);
    led.set_revocation(&pk, &rh, 1000).unwrap();
    assert!(led.is_revoked(&pk));
    assert_eq!(led.get_revoke_hash(&pk), Some(&rh));
}

// --- Revocation idempotent ---
#[test]
fn revocation_idempotent() {
    let mut led = Ledger::new();
    let pk = sender(1);
    let rh = hash(0xEE);
    led.set_revocation(&pk, &rh, 1000).unwrap();
    led.set_revocation(&pk, &rh, 1000).unwrap(); // idempotent
    assert_eq!(led.revocation_count(), 1);
}

// --- Revocation divergence ---
#[test]
fn revocation_divergence() {
    let mut led = Ledger::new();
    let pk = sender(1);
    led.set_revocation(&pk, &hash(0xAA), 1000).unwrap();
    let result = led.set_revocation(&pk, &hash(0xBB), 2000);
    assert_eq!(result, Err(LedgerError::Divergence));
}

// --- Kill-proof: dedupe BEFORE capacity (re-send on FULL store succeeds) ---
#[test]
fn dedupe_before_capacity_resend_on_full_succeeds() {
    let mut led = Ledger::new();
    // Fill the store to capacity.
    for i in 0..MAX_ENVELOPES {
        led.insert_envelope(EnvelopeEntry {
            hash: hash(i as u8),
            sender: sender((i % 256) as u8),
            channel: channel(0),
            seq: i as u64,
        })
        .unwrap();
    }
    assert_eq!(led.envelope_count(), MAX_ENVELOPES);

    // Re-send the FIRST envelope (same sender, channel, seq, same hash) → must succeed.
    let result = led.insert_envelope(EnvelopeEntry {
        hash: hash(0),
        sender: sender(0),
        channel: channel(0),
        seq: 0,
    });
    assert!(result.is_ok(), "re-send of stored envelope must succeed on FULL store");

    // New envelope on full store → StoreFull.
    let result = led.insert_envelope(EnvelopeEntry {
        hash: hash(0xFF),
        sender: sender(0xFF),
        channel: channel(0xFF),
        seq: 99999,
    });
    assert_eq!(result, Err(LedgerError::StoreFull));
}

// --- Envelope equivocation: same (sender, channel, seq) different hash → Divergence ---
#[test]
fn envelope_equivocation_diverges() {
    let mut led = Ledger::new();
    led.insert_envelope(EnvelopeEntry {
        hash: hash(0xAA),
        sender: sender(1),
        channel: channel(1),
        seq: 42,
    })
    .unwrap();
    let result = led.insert_envelope(EnvelopeEntry {
        hash: hash(0xBB), // different hash
        sender: sender(1),
        channel: channel(1),
        seq: 42, // same seq
    });
    assert_eq!(result, Err(LedgerError::Divergence));
}

// --- Seq window: first call seeds, subsequent checks work ---
#[test]
fn seq_window_first_call_seeds() {
    let mut led = Ledger::new();
    let s = sender(1);
    let c = channel(1);
    led.check_seq(&s, &c, 100).unwrap(); // seeds window
    assert_eq!(led.seq_window_count(), 1);
    // Higher seq accepted.
    led.check_seq(&s, &c, 101).unwrap();
}

// --- Seq window: stale seq rejected ---
#[test]
fn seq_window_stale_rejected() {
    let mut led = Ledger::new();
    let s = sender(1);
    let c = channel(1);
    // Seed at 2000: window covers [2000-1023, 2000] = [977, 2000].
    led.check_seq(&s, &c, 2000).unwrap();
    // Seq 1 < 977 → below window → stale.
    let result = led.check_seq(&s, &c, 1);
    assert_eq!(result, Err(LedgerError::WindowStale));
}

// --- F10 revocation pruning: evict lowest cert_expiry_ms when full ---
#[test]
fn f10_revocation_pruning_evicts_lowest_expiry() {
    let mut led = Ledger::new();
    // Fill revocations to capacity with increasing expiry.
    for i in 0..MAX_REVOCATIONS {
        let pk = sender(i as u8);
        led.set_revocation(&pk, &hash(i as u8), (i as u64 + 1) * 1000)
            .unwrap();
    }
    assert_eq!(led.revocation_count(), MAX_REVOCATIONS);

    // New revocation with higher expiry → evicts the lowest (sender(0), expiry=1000).
    let new_pk = sender(0xFF);
    led.set_revocation(&new_pk, &hash(0xFF), 999_999).unwrap();
    assert_eq!(led.revocation_count(), MAX_REVOCATIONS); // still at capacity
    assert!(!led.is_revoked(&sender(0))); // evicted
    assert!(led.is_revoked(&new_pk)); // new one present
}

// --- F5: parents-before-seq — if parents fail, seq NOT advanced ---
#[test]
fn f5_parents_before_seq_seq_not_advanced_on_parent_failure() {
    use bolina::transport::verify::{verify_envelope_admission, VerifyError};

    let mut led = Ledger::new();
    let s = sender(1);
    let c = channel(1);
    let h = hash(0xAA);

    // Parents list includes a hash NOT in the ledger → should fail.
    let parents = [hash(0xFF)];
    let result = verify_envelope_admission(&mut led, &h, &s, &c, 100, &parents);
    assert_eq!(result, Err(VerifyError::UnknownParents));

    // Seq window should NOT have been created (parents failed first).
    assert_eq!(led.seq_window_count(), 0);
}

// --- F5 happy path: parents present → seq checked → envelope inserted ---
#[test]
fn f5_happy_path_admission_succeeds() {
    use bolina::transport::verify::verify_envelope_admission;

    let mut led = Ledger::new();

    // Pre-populate parent envelope.
    let parent_hash = hash(0x01);
    led.insert_envelope(EnvelopeEntry {
        hash: parent_hash,
        sender: sender(99),
        channel: channel(99),
        seq: 0,
    })
    .unwrap();

    let s = sender(1);
    let c = channel(1);
    let h = hash(0xBB);
    let parents = [parent_hash];

    let result = verify_envelope_admission(&mut led, &h, &s, &c, 100, &parents);
    assert!(result.is_ok());
    assert_eq!(led.envelope_count(), 2); // parent + new
    assert_eq!(led.seq_window_count(), 1);
}
