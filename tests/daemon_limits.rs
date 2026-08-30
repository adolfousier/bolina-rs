//! Daemon boundary tests — kill mutants in handle_datagram/handshake/transport.

use bolina::daemon::Daemon;
use std::net::UdpSocket;
use tempfile::TempDir;

#[test]
fn handle_datagram_ignores_zero_length() {
    let dir = TempDir::new().unwrap();
    let mut d = Daemon::new("127.0.0.1:0", dir.path()).unwrap();
    let _ = d.handle_datagram(&[], "127.0.0.1:1234".parse().unwrap());
}

#[test]
fn handle_datagram_ignores_unknown_type() {
    let dir = TempDir::new().unwrap();
    let mut d = Daemon::new("127.0.0.1:0", dir.path()).unwrap();
    let _ = d.handle_datagram(&[255, 0, 0], "127.0.0.1:1234".parse().unwrap());
}

#[test]
fn handle_handshake_ignores_short_msg() {
    let dir = TempDir::new().unwrap();
    let mut d = Daemon::new("127.0.0.1:0", dir.path()).unwrap();
    let _ = d.handle_datagram(&[1, 0, 0, 0], "127.0.0.1:1234".parse().unwrap());
}

#[test]
fn handle_transport_ignores_short_msg() {
    let dir = TempDir::new().unwrap();
    let mut d = Daemon::new("127.0.0.1:0", dir.path()).unwrap();
    let _ = d.handle_datagram(&[4, 0, 0, 0], "127.0.0.1:1234".parse().unwrap());
}

#[test]
fn session_table_lookup_returns_none_for_unknown() {
    let dir = TempDir::new().unwrap();
    let d = Daemon::new("127.0.0.1:0", dir.path()).unwrap();
    assert!(d.lookup_session(999).is_none());
}

#[test]
fn session_table_sessions_starts_at_zero() {
    let dir = TempDir::new().unwrap();
    let d = Daemon::new("127.0.0.1:0", dir.path()).unwrap();
    assert_eq!(d.sessions(), 0);
}
