//! W5 sync tests — port of sync_test.zig (8 tests)

use bolina::transport::sync::*;

#[test]
fn rate_window_admit_within_budget() {
    let mut w = RateWindow::new(SERVE_BUDGET);
    for i in 0..SERVE_BUDGET {
        assert!(w.admit(RATE_WINDOW_MS, 1000 + i as u64 * 100));
    }
    // 9th in window refused
    assert!(!w.admit(RATE_WINDOW_MS, 1000 + 900));
}

#[test]
fn rate_window_slides_by_time() {
    let mut w = RateWindow::new(SERVE_BUDGET);
    for i in 0..SERVE_BUDGET {
        assert!(w.admit(RATE_WINDOW_MS, 1000 + i as u64 * 100));
    }
    // After window expires, admit again
    assert!(w.admit(RATE_WINDOW_MS, 1000 + RATE_WINDOW_MS + 100));
}

#[test]
fn rate_table_admit_known_peer() {
    let mut t = RateTable::new(SERVE_BUDGET);
    let peer = [0xAA; 32];
    for i in 0..SERVE_BUDGET {
        assert!(t.admit(peer, RATE_WINDOW_MS, 1000 + i as u64 * 100));
    }
    assert!(!t.admit(peer, RATE_WINDOW_MS, 1000 + 900));
    assert_eq!(t.used(), 1);
}

#[test]
fn rate_table_full_refuses_new_peer() {
    let mut t = RateTable::new(SERVE_BUDGET);
    for i in 0..MAX_TRACKED_PEERS {
        let mut peer = [0u8; 32];
        peer[0] = (i & 0xFF) as u8;
        assert!(t.admit(peer, RATE_WINDOW_MS, 1000));
    }
    // New peer refused
    let new_peer = [0xFF; 32];
    assert!(!t.admit(new_peer, RATE_WINDOW_MS, 1000));
}

#[test]
fn build_response_empty() {
    let mut out = [0u8; MAX_RESPONSE_BYTES];
    let channel_id = [0xAA; 32];
    let result = build_response(&mut out, channel_id, &[], &[]);
    assert_eq!(result.count, 0);
    assert!(!result.truncated);
    assert_eq!(result.bytes_written, RESPONSE_HEADER);
    assert_eq!(out[33], 0);
}

#[test]
fn build_response_appends_envelopes() {
    let mut out = [0u8; MAX_RESPONSE_BYTES];
    let channel_id = [0xAA; 32];
    let items = vec![
        ServeItem { hash: [1; 32], wire: vec![0x01, 0x02, 0x03] },
        ServeItem { hash: [2; 32], wire: vec![0x04, 0x05] },
    ];
    let result = build_response(&mut out, channel_id, &items, &[]);
    assert_eq!(result.count, 2);
    assert!(!result.truncated);
    assert_eq!(out[33], 2);
}

#[test]
fn build_response_skips_have_hashes() {
    let mut out = [0u8; MAX_RESPONSE_BYTES];
    let channel_id = [0xAA; 32];
    let items = vec![
        ServeItem { hash: [1; 32], wire: vec![0x01] },
        ServeItem { hash: [2; 32], wire: vec![0x02] },
    ];
    let have = vec![[1; 32]]; // peer has first
    let result = build_response(&mut out, channel_id, &items, &have);
    assert_eq!(result.count, 1);
    assert_eq!(out[33], 1);
}

#[test]
fn build_response_truncates_at_envelope_ceiling() {
    let mut out = [0u8; MAX_RESPONSE_BYTES];
    let channel_id = [0xAA; 32];
    let items: Vec<ServeItem> = (0..65).map(|i| {
        let mut hash = [0u8; 32];
        hash[0] = i as u8;
        ServeItem { hash, wire: vec![i as u8] }
    }).collect();
    let result = build_response(&mut out, channel_id, &items, &[]);
    assert_eq!(result.count, MAX_RESPONSE_ENVELOPES);
    assert!(result.truncated);
}
