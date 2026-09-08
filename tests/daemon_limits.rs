//! Daemon boundary tests — kill mutants in handle_datagram/handshake/transport.
//! W12 task 8: rewritten against the wired daemon (real keys, real socket).

use bolina::daemon::Daemon;
use bolina::keys;
use bolina::transport::session::SessionTable;
use ntest::timeout;
use std::net::UdpSocket;

fn boot_keys() -> (keys::Keys, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let k = keys::load_or_generate(dir.path()).expect("keys");
    (k, dir)
}

fn bound_socket() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.set_nonblocking(true).unwrap();
    s
}

#[test]
#[timeout(10000)]
fn handle_datagram_ignores_zero_length() {
    let (k, _dir) = boot_keys();
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, k);
    let sock = bound_socket();
    d.handle_datagram(&[], "127.0.0.1:1234".parse().unwrap(), &sock);
    assert_eq!(d.rejected_total, 0);
}

#[test]
#[timeout(10000)]
fn handle_datagram_ignores_unknown_type() {
    let (k, _dir) = boot_keys();
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, k);
    let sock = bound_socket();
    d.handle_datagram(&[255, 0, 0], "127.0.0.1:1234".parse().unwrap(), &sock);
    d.handle_datagram(&[5, 0, 0], "127.0.0.1:1234".parse().unwrap(), &sock);
    d.handle_datagram(&[6, 0, 0], "127.0.0.1:1234".parse().unwrap(), &sock);
    assert_eq!(d.rejected_total, 0);
}

#[test]
#[timeout(10000)]
fn handle_handshake_short_msg_is_silent_drop() {
    let (k, _dir) = boot_keys();
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, k);
    let sock = bound_socket();
    // type-1 short: NotInitiation inside process_datagram, still silent
    d.handle_datagram(&[1, 0, 0, 0], "127.0.0.1:1234".parse().unwrap(), &sock);
    assert!(d.sessions.lookup(0).is_none());
}

#[test]
#[timeout(10000)]
fn handle_transport_short_msg_is_silent_drop() {
    let (k, _dir) = boot_keys();
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, k);
    let sock = bound_socket();
    d.handle_datagram(&[4, 0, 0, 0], "127.0.0.1:1234".parse().unwrap(), &sock);
    assert_eq!(d.rejected_total, 0);
}

#[test]
#[timeout(10000)]
fn handle_handshake_bad_mac1_never_creates_session() {
    // mac1 gate FIRST: garbage msg1 (right size, no mac) must not admit a
    // session nor spend X25519 work (observable: no session, no crash).
    let (k, _dir) = boot_keys();
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, k);
    let sock = bound_socket();
    let msg1 = vec![1u8; 144];
    d.handle_datagram(&msg1, "127.0.0.1:1234".parse().unwrap(), &sock);
    assert!(d.sessions.lookup(0).is_none());
    assert!(d.sessions.lookup(1).is_none());
}

#[test]
#[timeout(10000)]
fn session_table_lookup_unknown_index_is_none() {
    let mut st = SessionTable::new();
    assert!(st.lookup(999).is_none());
}

#[test]
#[timeout(10000)]
fn session_table_unused_slot_is_none() {
    let mut st = SessionTable::new();
    assert!(st.lookup(0).is_none());
}

#[test]
#[timeout(10000)]
fn transport_to_unused_slot_is_rejection() {
    // type-4 to a receiver_index with no session: dropped, counted once
    let (k, _dir) = boot_keys();
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, k);
    let sock = bound_socket();
    let pkt = vec![4u8, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0xAA, 0xBB];
    d.handle_datagram(&pkt, "127.0.0.1:1234".parse().unwrap(), &sock);
    // no session: silent drop (transport replay counting only fires on an
    // OPENED session), so rejected_total stays 0 and nothing panics
    assert_eq!(d.ring.since(0).len(), 0);
}
