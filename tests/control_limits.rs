//! Control plane limit tests — kill mutants in poll_readable/write_response.

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

#[test]
fn healthz_request_passes() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(50));
    
    let mut client = connect_to(addr);
    client.write_all(b"GET /healthz HTTP/1.1\r\n\r\n").unwrap();
    client.flush().unwrap();
    
    sleep(Duration::from_millis(50));
    for _ in 0..50 {
        let _ = cp.poll_tick();
        if cp.clients.is_empty() { break; }
        sleep(Duration::from_millis(10));
    }
    
    let mut buf = vec![0u8; 8192];
    match client.read(&mut buf) {
        Ok(n) => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(resp.contains("200 OK"));
        }
        Err(_) => panic!("no response"),
    }
}

#[test]
fn invalid_method_fails() {
    let mut cp = ControlPlane::new(bind_any()).unwrap();
    let addr = cp.listener.local_addr().unwrap();
    sleep(Duration::from_millis(50));
    
    let mut client = connect_to(addr);
    client.write_all(b"POST /healthz HTTP/1.1\r\n\r\n").unwrap();
    client.flush().unwrap();
    
    sleep(Duration::from_millis(50));
    for _ in 0..50 {
        let _ = cp.poll_tick();
        if cp.clients.is_empty() { break; }
        sleep(Duration::from_millis(10));
    }
    
    let mut buf = vec![0u8; 8192];
    match client.read(&mut buf) {
        Ok(n) => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(resp.contains("501"));
        }
        Err(_) => panic!("no response"),
    }
}
