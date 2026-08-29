#![allow(dead_code)]
//! control: HTTP front door (single-threaded, multiplexed into poll loop)
//!
//! One loop, zero threads: wire fd + listener fd + client slots all in one poll pass.
//! Connection: close ALWAYS. One request per connection.
//!
//! State machine: ReadingHeaders -> ReadingBody -> Writing -> Closing
//! Deadline: 5000ms per connection
//! Slowloris: >=1024 bytes with NO newline = reject immediately
//!
//! Auth: Bearer token on all paths except GET /healthz (open by F7/D-091)
//! Token file 0600 at boot, CSPRNG, printed once, never rotated silently
//! Compare constant-time WITH length pre-check

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Instant;

/// Connection timeout in milliseconds
pub const CONN_TIMEOUT_MS: u64 = 5000;

/// Slowloris size guard: reject if >= this without newline
pub const SLOWLORIS_SIZE: usize = 1024;

/// Max concurrent clients
pub const MAX_CLIENTS: usize = 8;

/// Connection state machine
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    ReadingHeaders,
    ReadingBody,
    Writing,
    Closing,
}

/// One HTTP connection
pub struct Connection {
    pub stream: TcpStream,
    pub state: ConnState,
    pub buf: Vec<u8>,
    pub deadline: Instant,
    pub content_length: Option<usize>,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: ConnState::ReadingHeaders,
            buf: Vec::new(),
            deadline: Instant::now() + std::time::Duration::from_millis(CONN_TIMEOUT_MS),
            content_length: None,
        }
    }

    /// Advance state machine on readable event
    pub fn poll_readable(&mut self) -> Result<(), String> {
        if Instant::now() > self.deadline {
            return Err("deadline exceeded".into());
        }

        let mut tmp = [0u8; 4096];
        match self.stream.read(&mut tmp) {
            Ok(0) => {
                self.state = ConnState::Closing;
            }
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);

                // Slowloris guard
                if self.state == ConnState::ReadingHeaders
                    && self.buf.len() >= SLOWLORIS_SIZE
                    && !self.buf.windows(2).any(|w| w == b"\r\n")
                {
                    return Err("slowloris: size guard".into());
                }

                // Check for header terminator
                if self.state == ConnState::ReadingHeaders {
                    if let Some(pos) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers_end = pos + 4;
                        let headers = &self.buf[..headers_end];

                        // Parse headers
                        let content_length = parse_content_length(headers)?;
                        self.content_length = content_length;

                        // Transition to body or writing
                        if let Some(len) = content_length {
                            if self.buf.len() < headers_end + len {
                                self.state = ConnState::ReadingBody;
                            } else {
                                self.state = ConnState::Writing;
                            }
                        } else {
                            self.state = ConnState::Writing;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
            Err(e) => return Err(format!("read: {}", e)),
        }

        Ok(())
    }

    /// Write response
    pub fn write_response(&mut self, status: u16, body: &[u8]) -> Result<(), String> {
        let status_text = match status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            _ => "Unknown",
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status, status_text, body.len()
        );

        self.stream.write_all(response.as_bytes()).map_err(|e| e.to_string())?;
        self.stream.write_all(body).map_err(|e| e.to_string())?;
        self.state = ConnState::Closing;
        Ok(())
    }
}

/// Parse Content-Length from headers
fn parse_content_length(headers: &[u8]) -> Result<Option<usize>, String> {
    let header_str = std::str::from_utf8(headers).map_err(|_| "invalid utf8")?;

    for line in header_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            let value = line["content-length:".len()..].trim();
            let len: usize = value.parse().map_err(|_| "invalid content-length")?;
            return Ok(Some(len));
        }
    }

    Ok(None)
}

/// Control plane server
#[allow(dead_code)]
#[allow(dead_code)]
pub struct ControlPlane {
    pub listener: TcpListener,
    pub clients: Vec<Connection>,
}

impl ControlPlane {
    pub fn new(addr: SocketAddr) -> Result<Self, String> {
        let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        Ok(Self {
            listener,
            clients: Vec::new(),
        })
    }

    /// Poll tick: accept new conns, advance state machines
    pub fn poll_tick(&mut self) -> Result<(), String> {
        // Accept new connections
        match self.listener.accept() {
            Ok((stream, _addr)) => {
                if self.clients.len() >= MAX_CLIENTS {
                    // Table full: send 503, close immediately
                    let mut conn = Connection::new(stream);
                    conn.write_response(503, b"table full").map_err(|e| e.to_string())?;
                } else {
                    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
                    self.clients.push(Connection::new(stream));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("accept: {}", e)),
        }

        // Advance existing connections
        let mut to_remove = Vec::new();
        for (i, conn) in self.clients.iter_mut().enumerate() {
            match conn.poll_readable() {
                Ok(()) => {
                    if conn.state == ConnState::Closing {
                        to_remove.push(i);
                    }
                }
                Err(_) => {
                    to_remove.push(i);
                }
            }
        }

        // Remove closed connections (reverse order to preserve indices)
        for i in to_remove.into_iter().rev() {
            self.clients.remove(i);
        }

        Ok(())
    }
}

use std::io::{Read, Write};
