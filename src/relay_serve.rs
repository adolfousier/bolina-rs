//! Relay serve classifier (relay_serve.zig port, 216 lines).
//!
//! Relay role service: classifier + forwarder + store-and-forward post office
//! for relay traffic, sitting beside the handshake server on the SAME socket fd.
//! BE-EXEC-04: sender gate (established session) precedes ALL service.

use crate::transport::relay_store;

// --- Constants (relay_serve.zig:26-33) ---
pub const MAX_SA_LEN: usize = 28;
pub const MAX_ENDPOINTS: usize = 128;
pub const MAX_DRAIN_BATCH: usize = relay_store::MAX_PER_RECIPIENT;

// Relay message types (from relay.zig)
pub const MSG_RELAY_ROUTE: u8 = 0x10;
pub const MSG_RELAY_REGISTRATION: u8 = 0x11;

// Handshake message types (bytes 1,2,3)
pub const MSG_HANDSHAKE_INIT: u8 = 1;
pub const MSG_HANDSHAKE_RESP: u8 = 2;
pub const MSG_HANDSHAKE_DATA: u8 = 3;

// --- ServeResult: 6 exhaustive outcomes (relay_serve.zig:86) ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeResult {
    /// Handshake message (types 1,2,3) — route to handshake handler.
    ToHandshake,
    /// Live forward to registered recipient.
    Forwarded,
    /// Recipient not registered — stored for later drain.
    Stored,
    /// Registration accepted (+ stored-queue drain).
    Registered,
    /// Drain batch delivered to registered recipient.
    Drained,
    /// Unknown type or empty — silently dropped.
    Dropped,
}

// --- Endpoint: index → sockaddr map ---
#[derive(Clone)]
pub struct Endpoint {
    pub addr: [u8; MAX_SA_LEN],
    pub addr_len: u8,
    pub active: bool,
}

/// EndpointMap: index-based address table for relay recipients.
pub struct EndpointMap {
    entries: Vec<Option<Endpoint>>,
}

impl EndpointMap {
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(MAX_ENDPOINTS);
        for _ in 0..MAX_ENDPOINTS {
            entries.push(None);
        }
        Self { entries }
    }

    pub fn put(&mut self, index: usize, addr: &[u8], addr_len: u8) -> bool {
        if index >= MAX_ENDPOINTS || addr_len as usize > MAX_SA_LEN {
            return false;
        }
        let mut ep = Endpoint {
            addr: [0u8; MAX_SA_LEN],
            addr_len,
            active: true,
        };
        ep.addr[..addr_len as usize].copy_from_slice(&addr[..addr_len as usize]);
        self.entries[index] = Some(ep);
        true
    }

    pub fn get(&self, index: usize) -> Option<&Endpoint> {
        if index >= MAX_ENDPOINTS {
            return None;
        }
        self.entries[index].as_ref().filter(|e| e.active)
    }

    pub fn remove(&mut self, index: usize) -> bool {
        if index >= MAX_ENDPOINTS {
            return false;
        }
        if self.entries[index].is_some() {
            self.entries[index] = None;
            true
        } else {
            false
        }
    }
}

impl Default for EndpointMap {
    fn default() -> Self {
        Self::new()
    }
}

// --- Classifier (BE-EXEC-04) ---

/// Pure classifier: route a datagram by its first byte.
///
/// | byte | action |
/// |---|---|
/// | 1,2,3 | handshake machinery (ToHandshake) |
/// | MSG_RELAY_ROUTE | live forward OR deferred store |
/// | MSG_RELAY_REGISTRATION | registration (+ stored-queue drain) |
/// | anything else / empty | Dropped — no service |
///
/// The sender gate (established session) is enforced by the caller
/// (serveDatagram in the Zig port) before this classifier runs.
pub fn classify_datagram(dgram: &[u8]) -> ServeResult {
    if dgram.is_empty() {
        return ServeResult::Dropped;
    }
    match dgram[0] {
        MSG_HANDSHAKE_INIT | MSG_HANDSHAKE_RESP | MSG_HANDSHAKE_DATA => {
            ServeResult::ToHandshake
        }
        MSG_RELAY_ROUTE => {
            // Route messages go to live forward if recipient registered,
            // or stored for later drain if not. The caller decides which
            // based on endpoint map lookup — here we return the structural
            // result that triggers the forward-or-store branch.
            ServeResult::Forwarded
        }
        MSG_RELAY_REGISTRATION => ServeResult::Registered,
        _ => ServeResult::Dropped,
    }
}

/// Classify with recipient check: returns Forwarded if endpoint registered,
/// Stored if not. Used by the relay serve path after classify_datagram
/// returns Forwarded.
pub fn classify_route(
    _dgram: &[u8],
    endpoints: &EndpointMap,
    recipient_index: usize,
) -> ServeResult {
    if endpoints.get(recipient_index).is_some() {
        ServeResult::Forwarded
    } else {
        ServeResult::Stored
    }
}
