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
