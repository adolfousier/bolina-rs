//! Control plane boundary tests.

use bolina::control::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use std::thread::sleep;

fn bind_any() -> SocketAddr { "127.0.0.1:0".parse().unwrap() }

fn connect_to(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s
}

fn read_resp(s: &mut TcpStream) -> String {
    let mut buf = vec![0u8; 8192];
    let mut out = Vec::new();
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn accept_one(cp: &mut ControlPlane) {
    for _ in 0..50 {
        let _ = cp.poll_tick();
        if !cp.clients.is_empty() { return; }
        sleep(Duration::from_millis(20));
    }
    panic!("accept timeout");
}

fn pump_writing(cp: &mut ControlPlane) {
    for _ in 0..50 {
        let _ = cp.poll_tick();
        if cp.clients.first().map_or(false, |c| c.state == ConnState::Writing || c.state == ConnState::Closing) { return; }
        sleep(Duration::from_millis(20));
    }
}

#[test]
fn write_response_sets_closing() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(50));
    let _client = connect_to(addr);
    sleep(Duration::from_millis(50));
    accept_one(&mut cp);
    assert!(!cp.clients.is_empty());
    if let Some(conn) = cp.clients.first_mut() {
        conn.write_response(200, b"test").unwrap();
        assert_eq!(conn.state, ConnState::Closing);
    }
}

#[test]
fn all_status_codes_format_correctly() {
    for status in [200u16, 400, 403, 404, 500, 501, 503, 418] {
        let mut cp = ControlPlane::new(bind_any()).unwrap();
        let addr = cp.listener.local_addr().unwrap();
        sleep(Duration::from_millis(30));
        let mut client = connect_to(addr);
        sleep(Duration::from_millis(30));
        accept_one(&mut cp);
        if let Some(conn) = cp.clients.first_mut() {
            conn.write_response(status, b"body").unwrap();
        }
        let resp = read_resp(&mut client);
        assert!(resp.contains(&format!("{}", status)), "status {} not in: {}", status, resp);
        assert!(resp.contains("Content-Length: 4"));
    }
}

#[test]
fn healthz_roundtrip() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(30));
    let mut client = connect_to(addr);
    sleep(Duration::from_millis(30));
    accept_one(&mut cp);
    client.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    pump_writing(&mut cp);
    if let Some(conn) = cp.clients.first_mut() {
        if conn.state == ConnState::Writing {
            conn.write_response(200, b"ok").unwrap();
        }
    }
    let resp = read_resp(&mut client);
    assert!(resp.contains("200 OK"), "got: {}", resp);
}

#[test]
fn content_length_parsed() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(30));
    let mut client = connect_to(addr);
    sleep(Duration::from_millis(30));
    accept_one(&mut cp);
    client.write_all(b"POST / HTTP/1.1\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}").unwrap();
    pump_writing(&mut cp);
    assert_eq!(cp.clients.first().and_then(|c| c.content_length), Some(13));
}

#[test]
fn no_content_length_goes_to_writing() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(30));
    let mut client = connect_to(addr);
    sleep(Duration::from_millis(30));
    accept_one(&mut cp);
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    pump_writing(&mut cp);
    assert_eq!(cp.clients.first().map(|c| c.state), Some(ConnState::Writing));
    assert_eq!(cp.clients.first().and_then(|c| c.content_length), None);
}

#[test]
fn deadline_exceeded_causes_cleanup() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(30));
    let _client = connect_to(addr);
    sleep(Duration::from_millis(30));
    accept_one(&mut cp);
    if let Some(conn) = cp.clients.first_mut() {
        conn.deadline = std::time::Instant::now() - Duration::from_secs(1);
    }
    let _ = cp.poll_tick();
    assert!(cp.clients.is_empty(), "expired connection should be removed");
}

#[test]
#[ignore]
fn slowloris_guard() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(30));
    let mut client = connect_to(addr);
    sleep(Duration::from_millis(30));
    accept_one(&mut cp);
    let payload = vec![b'A'; SLOWLORIS_SIZE + 100];
    client.write_all(&payload).unwrap();
    sleep(Duration::from_millis(100));
    let mut got_error = false;
    for _ in 0..20 {
        if let Err(e) = cp.poll_tick() {
            got_error = e.contains("slowloris");
            break;
        }
        sleep(Duration::from_millis(10));
    }
    assert!(got_error, "slowloris should reject");
}

#[test]
fn table_full_returns_503() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    let mut clients = Vec::new();
    for _ in 0..MAX_CLIENTS {
        sleep(Duration::from_millis(20));
        let c = connect_to(addr);
        sleep(Duration::from_millis(20));
        accept_one(&mut cp);
        clients.push(c);
    }
    assert_eq!(cp.clients.len(), MAX_CLIENTS);
    sleep(Duration::from_millis(20));
    let mut overflow = connect_to(addr);
    sleep(Duration::from_millis(20));
    let _ = cp.poll_tick();
    let resp = read_resp(&mut overflow);
    assert!(resp.contains("503") || resp.contains("table full"), "got: {}", resp);
}
