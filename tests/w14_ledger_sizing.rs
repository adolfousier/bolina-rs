//! W14 (ledger-loaded drain measurement, 2026-09-13/14): sizing of the
//! envelope-ledger cap. Daniel's question: `insert_envelope` scans all
//! stored envelopes linearly per fresh identity (ledger_envelope.rs), so at
//! the 4096 cap every arrival pays the full scan. Does that cost break the
//! pacing budget (10ms per 100-envelope batch = 100µs/envelope)?
//!
//! Why deterministic in-process: the live soak cannot reach the cap (the
//! 16-slot handshake table dies after ~4 rounds of load first, ledger
//! peaked ~1220 live), so the 4096 case is answered here instead of by a
//! soak that structurally cannot reach it.
//!
//! Scope honesty (Daniel, 2026-09-14): the per-envelope ledger cost has
//! two terms — dedup-insert and parent-check (`all_parents_present`, a
//! nested linear scan, the dominant one: ~6x the insert at 8 parents on
//! the target). Both terms are measured here; neither includes verify or
//! fsync. Every machine claims its own number, so docs cite ranges, not
//! a single run's value.

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

/// Term 1/2: the dedup scan for a fresh identity at a full ledger.
/// Warm-path timing (two rejections first, so the branch predictor and
/// caches see the loop): the test PRINTS its own number, it is not a
/// constant quoted by any doc. The 10ms ceiling here is
/// gross-misbehaviour insurance; the µs claim is the printed value, so
/// every reader machine re-derives its own.
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
        "w14 insert-dedup at {MAX_ENVELOPES} cap: {us}µs (budget 100µs/envelope; the dominant parent-check term is timed by its own test)"
    );
    assert!(us < 10_000, "capped dedup scan took {us}µs, ceiling 10ms");
}

/// Term 2/2 (the dominant one): `all_parents_present` with 8 parents on
/// a full ledger. The inner scan short-circuits on FIND, so the worst
/// case is not 8 random parents, it is 8 parents at the END of the
/// store: every inner `any()` walks almost the whole vector. This is the
/// term Daniel measured at 46.40µs on the target at 4000 occupancy, and
/// the one missing from the first version of this file.
#[test]
fn parent_check_at_cap_is_dominant_but_fits() {
    let led = filled();
    // 8 parents, the last slots of the store: maximum inner-scan length.
    let parents: Vec<[u8; HASH_BYTES]> =
        (0..8).map(|k| entry(MAX_ENVELOPES - 1 - k).hash).collect();
    // warm the call path once (caches, branch behaviour).
    assert!(led.all_parents_present(&parents));
    let t0 = Instant::now();
    let ok = led.all_parents_present(&parents);
    let us = t0.elapsed().as_micros();
    assert!(ok, "worst-case parents must all be found");
    // Contrasting case: an absent parent FIRST in the list ends the check
    // after ONE inner scan (1 walk, not 8) — proves the timed number
    // above is the 8-walk worst case, not a constant of the call.
    let mut missing = [0u8; HASH_BYTES];
    missing[..8].copy_from_slice(&(999_999usize as u64).to_le_bytes());
    let mut missing_first = parents.clone();
    missing_first[0] = missing;
    let t1 = Instant::now();
    assert!(!led.all_parents_present(&missing_first));
    let us_absent = t1.elapsed().as_micros();
    println!(
        "w14 parents8-worst-case at {MAX_ENVELOPES} cap: {us}µs (1-scan absent-parent control: {us_absent}µs)"
    );
    assert!(us < 10_000, "capped parent check took {us}µs, ceiling 10ms");
}
