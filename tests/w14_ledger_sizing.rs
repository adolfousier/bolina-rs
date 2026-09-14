//! W14 (ledger-loaded drain measurement, 2026-09-13): sizing of the
//! envelope-ledger cap. Daniel's question: `insert_envelope` scans all
//! stored envelopes linearly per fresh identity (ledger_envelope.rs), so at
//! the 4096 cap every arrival pays the full scan. Does that cost break the
//! pacing budget (10ms per 100-envelope batch = 100µs/envelope)?
//!
//! Why deterministic in-process: the live soak could never reach the cap
//! (the 16-slot handshake table dies at round ~13 rounds of load first,
//! ledger peaked ~1220 live), so the 4096 case is answered here instead of
//! by a soak that structurally cannot reach it.

use bolina::ledger_envelope::{
    EnvelopeEntry, Ledger, LedgerError, HASH_BYTES, LEN_CHANNEL_ID, LEN_SIG_PUBKEY, MAX_ENVELOPES,
};
use std::time::Instant;

fn entry(seq: usize) -> EnvelopeEntry {
    let mut hash = [0u8; HASH_BYTES];
    hash[..8].copy_from_slice(&(seq as u64).to_le_bytes());
    EnvelopeEntry {
        hash,
        sender: [0xA5; LEN_SIG_PUBKEY],
        channel: [0x5A; LEN_CHANNEL_ID],
        seq: seq as u64,
    }
}

fn filled() -> Ledger {
    let mut led = Ledger::new();
    for i in 0..MAX_ENVELOPES {
        led.insert_envelope(entry(i)).expect("fill below cap");
    }
    led
}

/// The cap branch counts the scan-completed rejection in BOTH counters
/// (work done, not accepted), freezes store growth, and a re-send of a
/// stored envelope on a FULL store still short-circuits idempotent
/// (BE-ENV-05 order-first rule: dedupe before capacity).
#[test]
fn cap_storefull_is_counted_and_inserted_stops_filling() {
    let mut led = filled();
    assert_eq!(led.envelope_count(), MAX_ENVELOPES);
    assert_eq!(led.inserts_total, MAX_ENVELOPES as u64);
    assert_eq!(led.storefull_total, 0);

    // fresh identity at cap: rejected, counted as work done, no growth.
    assert_eq!(
        led.insert_envelope(entry(MAX_ENVELOPES)),
        Err(LedgerError::StoreFull)
    );
    assert_eq!(led.storefull_total, 1);
    assert_eq!(led.inserts_total, MAX_ENVELOPES as u64 + 1);
    assert_eq!(led.envelope_count(), MAX_ENVELOPES);

    // stored identity re-sent on a FULL store: idempotent Ok, counters
    // frozen (the scan matched before the capacity branch).
    assert!(led.insert_envelope(entry(7)).is_ok());
    assert_eq!(led.inserts_total, MAX_ENVELOPES as u64 + 1);
    assert_eq!(led.storefull_total, 1);
    assert_eq!(led.envelope_count(), MAX_ENVELOPES);
}

/// The last fresh insertion at a full ledger costs a full 4096-entry scan.
/// Warm-path timing (two rejections first, so the branch predictor and
/// caches see the loop): 6µs in the run that landed this test (the test
/// prints its number), budget 100µs/envelope — pacing stays valid at cap.
/// The 10ms ceiling here is gross-misbehaviour
/// insurance, not the claim: the claim is the printed µs.
#[test]
fn last_insertion_at_cap_is_cheap() {
    let mut led = filled();
    for k in 0..2 {
        // warm the rejection path (also the first cold passes of the scan)
        let _ = led.insert_envelope(entry(MAX_ENVELOPES + k));
    }
    let t0 = Instant::now();
    let res = led.insert_envelope(entry(MAX_ENVELOPES + 2));
    let us = t0.elapsed().as_micros();
    assert_eq!(res, Err(LedgerError::StoreFull));
    assert_eq!(led.envelope_count(), MAX_ENVELOPES);
    println!(
        "w14: fresh-identity scan at {MAX_ENVELOPES}-entry cap: {us}µs (budget 100µs/envelope)"
    );
    assert!(us < 10_000, "capped scan took {us}µs, ceiling 10ms");
}
