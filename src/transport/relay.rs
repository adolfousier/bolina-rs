//! relay.rs — mesh registration + route frames + routing table
//!
//! Port of src/relay.zig (255 lines) + relay_test.zig (328 lines).
//! BE-MESH-02/05. MD5 heritage: dedup-first insert.


// --- Constants ---

pub const MSG_RELAY_ROUTE: u8 = 5;
pub const MSG_RELAY_REGISTRATION: u8 = 6;
pub const DOMAIN_RELAY_REGISTRATION: u8 = 0x07;

pub const LEN_RELAY_ROUTE: usize = 20;
pub const LEN_RELAY_REGISTRATION: usize = 124;
pub const LEN_RESERVED: usize = 3;
pub const LEN_OVERLAY_ADDR: usize = 16;
pub const LEN_SIG: usize = 64;
pub const LEN_PADDING: usize = 16;

pub const MAX_RELAY_TABLE: usize = 4096;
pub const TIMESTAMP_SKEW: u64 = 300;
pub const MAX_EXPIRY: u64 = 86400;

// --- Errors ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    WrongType,
    NonZeroReserved,
    TrailingBytes,
    Truncated,
    ExpiryTooLong,
    StaleRoute,
    UnknownRecipient,
}

pub type Result<T> = std::result::Result<T, RelayError>;

// --- RelayRoute (type 5, 20 bytes) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRoute {
    pub sender_index: u32,
    pub recipient_index: u32,
    pub timestamp: u64,
}

impl RelayRoute {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() != LEN_RELAY_ROUTE { return Err(RelayError::Truncated); }
        if buf[0] != MSG_RELAY_ROUTE { return Err(RelayError::WrongType); }
        if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 { return Err(RelayError::NonZeroReserved); }
        let sender_index = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let recipient_index = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let timestamp = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        Ok(Self { sender_index, recipient_index, timestamp })
    }

    pub fn encode(&self, out: &mut [u8]) {
        out[0] = MSG_RELAY_ROUTE;
        out[1..4].fill(0);
        out[4..8].copy_from_slice(&self.sender_index.to_be_bytes());
        out[8..12].copy_from_slice(&self.recipient_index.to_be_bytes());
        out[12..20].copy_from_slice(&self.timestamp.to_be_bytes());
    }
}

// --- RelayRegistration (type 6, 124 bytes) ---

#[derive(Debug, Clone, PartialEq)]
pub struct RelayRegistration {
    pub relay_index: u32,
    pub client_index: u32,
    pub timestamp: u64,
    pub overlay_addr: [u8; LEN_OVERLAY_ADDR],
    pub expiry: u64,
    pub sig: [u8; LEN_SIG],
    pub tbs_len: usize,
}

impl RelayRegistration {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() != LEN_RELAY_REGISTRATION { return Err(RelayError::Truncated); }
        if buf[0] != MSG_RELAY_REGISTRATION { return Err(RelayError::WrongType); }
        if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 { return Err(RelayError::NonZeroReserved); }
        let relay_index = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let client_index = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let timestamp = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        let mut overlay_addr = [0u8; LEN_OVERLAY_ADDR];
        overlay_addr.copy_from_slice(&buf[20..36]);
        let expiry = u64::from_be_bytes(buf[36..44].try_into().unwrap());
        if expiry > MAX_EXPIRY { return Err(RelayError::ExpiryTooLong); }
        let mut sig = [0u8; LEN_SIG];
        sig.copy_from_slice(&buf[44..108]);
        // padding at 108..124, ignored
        let tbs_len = LEN_RELAY_REGISTRATION - LEN_SIG - LEN_PADDING; // = 44
        Ok(Self { relay_index, client_index, timestamp, overlay_addr, expiry, sig, tbs_len })
    }

    pub fn tbs<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[..self.tbs_len]
    }
}

// --- RelayEntry + RelayTable ---

#[derive(Debug, Clone, Copy)]
pub struct RelayEntry {
    pub overlay_addr: [u8; LEN_OVERLAY_ADDR],
    pub relay_index: u32,
    pub client_index: u32,
    pub expiry: u64,
}

pub struct RelayTable {
    entries: Vec<RelayEntry>,
}

impl RelayTable {
    pub fn new() -> Self { Self { entries: Vec::with_capacity(MAX_RELAY_TABLE) } }

    /// MD5 heritage: dedup by overlay_addr FIRST.
    /// Same addr => in-place refresh (return true).
    /// New addr at capacity => false.
    pub fn insert(&mut self, entry: RelayEntry) -> bool {
        for e in self.entries.iter_mut() {
            if e.overlay_addr == entry.overlay_addr {
                *e = entry;
                return true;
            }
        }
        if self.entries.len() >= MAX_RELAY_TABLE { return false; }
        self.entries.push(entry);
        true
    }

    pub fn lookup(&self, overlay_addr: &[u8]) -> Option<&RelayEntry> {
        self.entries.iter().find(|e| e.overlay_addr[..] == *overlay_addr)
    }

    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|e| e.expiry > now);
    }

    pub fn count(&self) -> usize { self.entries.len() }
}

// --- Forwarding (BE-MESH-02) ---

pub fn forward_packet<'a>(
    table: &RelayTable,
    route: &RelayRoute,
    packet: &'a [u8],
    now: u64,
) -> Result<&'a [u8]> {
    if route.timestamp > now + TIMESTAMP_SKEW || route.timestamp + TIMESTAMP_SKEW < now {
        return Err(RelayError::StaleRoute);
    }
    for e in &table.entries {
        if e.client_index == route.recipient_index {
            return Ok(packet);
        }
    }
    Err(RelayError::UnknownRecipient)
}
