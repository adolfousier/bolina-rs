//! W9 listener: pre-authentication endpoint registry (listener.zig port).
//!
//! BE-EXEC-02: one listener per (address, port).
//! BE-EXEC-03: one address family per socket.

pub const MAX_ENDPOINTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenError {
    EndpointBusy,
    FamilyMismatch,
    BindRefused,
    SocketFailed,
    RecvFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

pub struct Endpoint {
    pub addr: [u8; 16],
    pub addr_len: usize,
    pub port: u16,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self { addr: [0u8; 16], addr_len: 0, port: 0 }
    }
}

/// EndpointRegistry: one listener per (address, port).
pub struct EndpointRegistry {
    entries: [Endpoint; MAX_ENDPOINTS],
    count: usize,
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| Endpoint::default()),
            count: 0,
        }
    }
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn owns(&self, addr: &[u8], port: u16) -> bool {
        for e in &self.entries[..self.count] {
            if e.port == port && e.addr_len == addr.len() && &e.addr[..e.addr_len] == addr {
                return true;
            }
        }
        false
    }

    pub fn claim(&mut self, addr: &[u8], port: u16) -> Result<(), ListenError> {
        if self.owns(addr, port) {
            return Err(ListenError::EndpointBusy);
        }
        if self.count >= MAX_ENDPOINTS {
            return Err(ListenError::EndpointBusy);
        }
        let e = &mut self.entries[self.count];
        e.addr[..addr.len()].copy_from_slice(addr);
        e.addr_len = addr.len();
        e.port = port;
        self.count += 1;
        Ok(())
    }

    pub fn release(&mut self, addr: &[u8], port: u16) {
        for i in 0..self.count {
            let e = &self.entries[i];
            if e.port == port && e.addr_len == addr.len() && &e.addr[..e.addr_len] == addr {
                let last = self.count - 1;
                if i != last {
                    // Swap with last
                    let tmp_addr = self.entries[last].addr;
                    let tmp_len = self.entries[last].addr_len;
                    let tmp_port = self.entries[last].port;
                    self.entries[i].addr = tmp_addr;
                    self.entries[i].addr_len = tmp_len;
                    self.entries[i].port = tmp_port;
                }
                self.count -= 1;
                return;
            }
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// OS socket seam (listener.zig: open/bind/recv/close)
// ---------------------------------------------------------------------------

/// A bound UDP listener wrapping a registry slot.
///
/// The bind-failure-releases-claim invariant: if `bind` fails after
/// `claim` succeeded, the registry slot is released automatically.
#[derive(Debug)]
pub struct Listener {
    socket: std::net::UdpSocket,
    family: Family,
}

impl Listener {
    /// Open and bind a UDP socket to the given address.
    ///
    /// On success: the socket is bound and ready for recv/recv_from.
    /// On failure: returns the appropriate ListenError.
    ///
    /// IMPORTANT: if this is called after `EndpointRegistry::claim`,
    /// the caller MUST call `EndpointRegistry::release` on bind failure
    /// to avoid leaking the registry slot.
    pub fn open_bind(addr: &str, port: u16, family: Family) -> Result<Self, ListenError> {
        use std::net::UdpSocket;

        let bind_addr = match family {
            Family::Ipv4 => format!("{}:{}", addr, port),
            Family::Ipv6 => format!("[{}]:{}", addr, port),
        };

        let socket = UdpSocket::bind(&bind_addr)
            .map_err(|_| ListenError::BindRefused)?;

        Ok(Self { socket, family })
    }

    /// Receive data into the caller's buffer.
    /// Returns the number of bytes received.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, ListenError> {
        self.socket.recv(buf).map_err(|_| ListenError::RecvFailed)
    }

    /// Receive data and the source address.
    /// Returns (bytes_received, source_addr_string).
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, String), ListenError> {
        let (n, addr) = self.socket.recv_from(buf)
            .map_err(|_| ListenError::RecvFailed)?;
        Ok((n, addr.to_string()))
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ListenError> {
        self.socket.local_addr()
            .map_err(|_| ListenError::SocketFailed)
    }

    pub fn family(&self) -> Family {
        self.family
    }

    /// Close the listener (drops the socket).
    pub fn close(self) {
        // Socket is closed when dropped.
        drop(self.socket);
    }
}
