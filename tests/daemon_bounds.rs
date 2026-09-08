//! W5 daemon boundary tests — kill mutants in daemon.rs
//! W12 task 8: rewritten against the wired daemon (real keys, real socket).
//!
//! Targets:
//! - handle_datagram: empty packet, unknown type, types 5/6
//! - handle_handshake: len < 144, mac1 failure
//! - handle_transport: len < 16, no session lookup
//! - SHUTDOWN flag semantics
//! - SessionTable lookup bounds

use bolina::daemon::{install_shutdown_handler, Daemon};
use bolina::keys;
use bolina::transport::session::SessionTable;
use ntest::timeout;
use std::net::{SocketAddr, UdpSocket};

fn boot_keys() -> keys::Keys {
    let dir = tempfile::TempDir::new().expect("tempdir");
    keys::load_or_generate(dir.path()).expect("keys")
}

fn test_daemon() -> Daemon {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Daemon::new(addr, boot_keys())
}

fn sock() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_nonblocking(true).unwrap();
    s
}

const DST: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    7420,
);

#[test]
#[timeout(10000)]
fn empty_datagram_is_silent_drop() {
    let mut d = test_daemon();
    let s = sock();
    d.handle_datagram(&[], DST, &s);
}

#[test]
#[timeout(10000)]
fn unknown_msg_type_is_silent_drop() {
    let mut d = test_daemon();
    let s = sock();
    d.handle_datagram(&[0xFF, 0, 0, 0], DST, &s);
}

#[test]
#[timeout(10000)]
fn relay_types_5_6_are_dropped() {
    let mut d = test_daemon();
    let s = sock();
    let pkt5 = [5u8; 16];
    let pkt6 = [6u8; 16];
    d.handle_datagram(&pkt5, DST, &s);
    d.handle_datagram(&pkt6, DST, &s);
    assert_eq!(d.rejected_total, 0);
}

#[test]
#[timeout(10000)]
fn handshake_short_packet_is_dropped() {
    let mut d = test_daemon();
    let s = sock();
    // Type 1, only 143 bytes — below the 144 threshold
    let pkt = [1u8; 143];
    d.handle_datagram(&pkt, DST, &s);
    assert!(d.sessions.lookup(0).is_none());
}

#[test]
#[timeout(10000)]
fn handshake_exact_144_with_bad_mac1_is_dropped() {
    let mut d = test_daemon();
    let s = sock();
    // Type 1, exactly 144 bytes, mac1 all zeros — verify will fail
    let pkt = [1u8; 144];
    d.handle_datagram(&pkt, DST, &s);
    assert!(d.sessions.lookup(0).is_none());
}

#[test]
#[timeout(10000)]
fn transport_short_packet_is_dropped() {
    let mut d = test_daemon();
    let s = sock();
    // Type 4, only 15 bytes — below the 16 threshold
    let pkt = [4u8; 15];
    d.handle_datagram(&pkt, DST, &s);
}

#[test]
#[timeout(10000)]
fn transport_no_session_is_dropped() {
    let mut d = test_daemon();
    let s = sock();
    // Type 4, valid 16-byte header, receiver_index=0 — no session
    let mut pkt = [4u8; 32];
    pkt[4..8].copy_from_slice(&0u32.to_be_bytes());
    d.handle_datagram(&pkt, DST, &s);
    assert_eq!(d.ring.since(0).len(), 0);
}

#[test]
#[timeout(10000)]
fn transport_receiver_index_u32_max() {
    let mut d = test_daemon();
    let s = sock();
    let mut pkt = [4u8; 32];
    pkt[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    d.handle_datagram(&pkt, DST, &s);
    assert_eq!(d.ring.since(0).len(), 0);
}

#[test]
#[timeout(10000)]
fn session_table_empty_lookup_returns_none() {
    let mut st = SessionTable::new();
    assert!(st.lookup(0).is_none());
    assert!(st.lookup(1).is_none());
    assert!(st.lookup(100).is_none());
    assert!(st.lookup(u32::MAX).is_none());
}

#[test]
fn shutdown_handler_is_idempotent() {
    // First install
    install_shutdown_handler();
    // Second install: ctrlc returns Err but .ok() swallows it
    install_shutdown_handler();
}

#[test]
#[timeout(10000)]
fn single_byte_datagram_is_handled() {
    let mut d = test_daemon();
    let s = sock();
    // Single byte: type 0 (unknown)
    d.handle_datagram(&[0], DST, &s);
    // Type 2 (unknown)
    d.handle_datagram(&[2], DST, &s);
    // Type 3 (unknown)
    d.handle_datagram(&[3], DST, &s);
}
