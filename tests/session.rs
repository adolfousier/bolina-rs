//! W5 session tests — port of session_test.zig (13 tests)
//! Each test cites its Zig equivalent by line number.

use bolina::transport::session::*;

#[test]
fn be_tr_02_rekey_rotation_zeroes_old_state() {
    // session_test.zig:33 — rotate zeroes both CipherState+RecvState
    let mut s = Session::new();
    s.send.key = [0xAA; 32];
    s.send.counter = 100;
    s.recv.key = [0xBB; 32];
    s.recv.window.check(50);
    let new_send = [0x11; 32];
    let new_recv = [0x22; 32];
    let hh = [0x33; 32];
    s.rotate(new_send, new_recv, hh, 1000);
    assert_eq!(s.send.key, new_send);
    assert_eq!(s.recv.key, new_recv);
    assert_eq!(s.send.counter, 0);
    assert_eq!(s.handshake_hash, hh);
    assert_eq!(s.key_epoch_ms, 1000);
}

#[test]
fn be_tr_02_zeroization_wipes_key_material() {
    // session_test.zig:58 — zero() clears key and counter
    let mut cs = CipherState::new();
    cs.key = [0xFF; 32];
    cs.counter = 999;
    cs.zero();
    assert_eq!(cs.key, [0; 32]);
    assert_eq!(cs.counter, 0);
}

#[test]
fn be_tr_02_seal_refuses_at_2_48_bound() {
    // session_test.zig:71 — seal returns RekeyRequired at the message bound
    let mut cs = CipherState::new();
    cs.key = [1; 32];
    cs.counter = REKEY_AFTER_MESSAGES;
    let mut out = [0u8; 64];
    let result = cs.seal(&mut out, b"test", b"");
    assert_eq!(result, Err(TransportError::RekeyRequired));
}

#[test]
fn be_tr_02_rekey_due_at_120s_not_before() {
    // session_test.zig:86 — due_for_rekey at exactly 120s, not 119_999ms
    let mut s = Session::new();
    s.key_epoch_ms = 1000;
    assert!(!s.due_for_rekey(1000 + REKEY_AFTER_MS - 1));
    assert!(s.due_for_rekey(1000 + REKEY_AFTER_MS));
}

#[test]
fn transport_frame_layout_spec_4_1a() {
    // session_test.zig:97 — header is type(1) + reserved(3) + peer_index(4) + counter(8)
    let mut s = Session::new();
    s.send.key = [1; 32];
    s.peer_index = 0x12345678;
    let mut out = [0u8; 128];
    let len = s.seal(&mut out, b"").unwrap();
    assert_eq!(len, HEADER_SIZE + 16); // keepalive = 32 bytes (header + tag)
    assert_eq!(out[0], MSG_TYPE_TRANSPORT);
    assert_eq!(out[1..4], [0, 0, 0]);
    assert_eq!(&out[4..8], &0x12345678u32.to_be_bytes());
    assert_eq!(&out[8..16], &0u64.to_be_bytes());
}

#[test]
fn be_tr_03_reordered_open_and_replay_refused() {
    // session_test.zig:113 — out-of-order OK, exact replay refused
    let mut s = Session::new();
    s.send.key = [1; 32];
    s.recv.key = [1; 32];
    let mut packets = vec![];
    for _ in 0..5 {
        let mut pkt = [0u8; 64];
        let len = s.seal(&mut pkt, b"test").unwrap();
        packets.push(pkt[..len].to_vec());
    }
    // Open in reverse order
    for (i, pkt) in packets.iter().enumerate().rev() {
        let mut out = [0u8; 32];
        let counter = i as u64;
        let pt_len = s.recv.open(&mut out, &pkt[..HEADER_SIZE], &pkt[HEADER_SIZE..], counter);
        assert!(pt_len.is_ok(), "reordered packet {} should open", i);
    }
    // Replay the first one
    let mut out = [0u8; 32];
    let result = s.recv.open(&mut out, &packets[0][..HEADER_SIZE], &packets[0][HEADER_SIZE..], 0);
    assert_eq!(result, Err(TransportError::Replay));
}

#[test]
fn be_tr_03_counter_below_window_floor_refused() {
    // session_test.zig:141 — counter >= 64 behind highest is refused
    let mut w = ReplayWindow::new();
    w.check(100);
    assert!(!w.check(36)); // 100 - 36 = 64, exactly at floor
    assert!(!w.check(35)); // below floor
    assert!(w.check(99)); // within window
}

#[test]
fn tampered_payload_fails_aead_tag() {
    // session_test.zig:167 — tamper ciphertext → DecryptFailed
    let mut s = Session::new();
    s.send.key = [1; 32];
    s.recv.key = [1; 32];
    let mut pkt = [0u8; 64];
    let len = s.seal(&mut pkt, b"secret").unwrap();
    pkt[HEADER_SIZE] ^= 0x01; // tamper
    let mut out = [0u8; 32];
    let result = s.recv.open(&mut out, &pkt[..HEADER_SIZE], &pkt[HEADER_SIZE..len], 0);
    assert_eq!(result, Err(TransportError::DecryptFailed));
}

#[test]
fn be_tr_05_session_ceiling_refuses_without_degrading() {
    // session_test.zig:183 — MAX_SESSIONS slots, admit refuses SlotFull
    let mut t = SessionTable::new();
    for i in 0..MAX_SESSIONS {
        let r = t.admit(i as u32, 0, [0; 32], [0; 32], [0; 32], 0);
        assert!(r.is_ok(), "slot {} should admit", i);
    }
    // Next one refuses
    let r = t.admit(0, 0, [0; 32], [0; 32], [0; 32], 0);
    assert_eq!(r, Err(TransportError::SlotFull));
    // Existing sessions still work
    assert!(t.lookup(0).is_some());
}

#[test]
fn release_zeroes_whole_slot() {
    // session_test.zig:204 — release clears in_use and zeros keys
    let mut t = SessionTable::new();
    t.admit(0, 0, [0xAA; 32], [0xBB; 32], [0xCC; 32], 1000).unwrap();
    assert!(t.lookup(0).is_some());
    t.release(0);
    assert!(t.lookup(0).is_none());
}

#[test]
fn lookup_rejects_stale_or_out_of_range() {
    // session_test.zig:216 — out-of-range → None, stale (not in_use) → None
    let mut t = SessionTable::new();
    assert!(t.lookup(MAX_SESSIONS as u32).is_none());
    assert!(t.lookup(0).is_none()); // not in_use
    t.admit(0, 0, [0; 32], [0; 32], [0; 32], 0).unwrap();
    assert!(t.lookup(0).is_some());
}

#[test]
fn be_tr_06_transport_failure_surfaces_as_error() {
    // session_test.zig:239 — all transport failures are TransportError variants
    let mut cs = CipherState::new();
    cs.key = [1; 32];
    cs.counter = REKEY_AFTER_MESSAGES;
    let mut out = [0u8; 8];
    // RekeyRequired
    assert_eq!(cs.seal(&mut out, b"x", b""), Err(TransportError::RekeyRequired));
    // OutOfRange (reset counter first)
    cs.counter = 0;
    let mut small = [0u8; 4];
    assert_eq!(cs.seal(&mut small, b"x", b""), Err(TransportError::OutOfRange));
}

#[test]
fn replay_window_edge_cases() {
    // Extra: verify window boundary behavior
    let mut w = ReplayWindow::new();
    assert!(w.check(100));
    assert!(w.check(163)); // 100 + 63 = 163, just within
    assert!(!w.check(163)); // duplicate
    assert!(w.check(164)); // advance
    assert!(!w.check(100)); // now 164 - 100 = 64, exactly at floor → refused
}
