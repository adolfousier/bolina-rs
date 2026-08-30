//! Daemon boundary tests — kill mutants in handle_datagram/handshake/transport.

use bolina::daemon::{Daemon, Keys, SessionTable};
use std::net::SocketAddr;
use ntest::timeout;

fn dummy_keys() -> Keys {
    Keys {
        kex_secret: [0u8; 32],
        kex_pub: [0u8; 32],
        sig_secret: [0u8; 32],
        sig_pub: [0u8; 32],
    }
}

#[test]
#[timeout(10000)]
fn handle_datagram_ignores_zero_length() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, dummy_keys());
    let _ = d.handle_datagram(&[], "127.0.0.1:1234".parse().unwrap());
}

#[test]
#[timeout(10000)]
fn handle_datagram_ignores_unknown_type() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, dummy_keys());
    let _ = d.handle_datagram(&[255, 0, 0], "127.0.0.1:1234".parse().unwrap());
}

#[test]
#[timeout(10000)]
fn handle_handshake_ignores_short_msg() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, dummy_keys());
    let _ = d.handle_datagram(&[1, 0, 0, 0], "127.0.0.1:1234".parse().unwrap());
}

#[test]
#[timeout(10000)]
fn handle_transport_ignores_short_msg() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut d = Daemon::new(addr, dummy_keys());
    let _ = d.handle_datagram(&[4, 0, 0, 0], "127.0.0.1:1234".parse().unwrap());
}

#[test]
#[timeout(10000)]
fn session_table_lookup_returns_none_for_unknown() {
    let st = SessionTable::new();
    assert!(st.lookup(999).is_none());
}

#[test]
#[timeout(10000)]
fn session_table_sessions_starts_at_zero() {
    let st = SessionTable::new();
    assert_eq!(st.sessions(), 0);
}
