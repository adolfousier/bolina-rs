//! session.rs — transport sessions after handshake completion
//!
//! Port of `src/session.zig` (215 lines) + `src/session_test.zig` (13 tests).
//!
//! BE-TR-02 (key rotation + zeroization), BE-TR-03 (replay window),
//! BE-TR-06 (type 4 framing). D-049 discipline: closed error enum.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

use super::noise;

// --- Constants (cite these exactly) ---

pub const MAX_SESSIONS: usize = 512;
pub const REKEY_AFTER_MS: u64 = 120_000;
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 48;
pub const HEADER_SIZE: usize = 16;
pub const MSG_TYPE_TRANSPORT: u8 = 4;

// --- Error set (closed, D-049) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    RekeyRequired,
    DecryptFailed,
    Replay,
    SlotFull,
    OutOfRange,
    NotBound,
}

pub type Result<T> = std::result::Result<T, TransportError>;

// --- Replay window (BE-TR-03) ---

#[derive(Clone, Copy)]
pub struct ReplayWindow {
    highest: u64,
    mask: u64,
}

impl ReplayWindow {
    pub fn new() -> Self { Self { highest: 0, mask: 0 } }

    /// Returns true iff the counter is fresh. Records the counter only
    /// if the caller commits it after the AEAD tag verifies.
    pub fn check(&mut self, counter: u64) -> bool {
        if self.highest == 0 {
            self.highest = counter;
            self.mask = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift >= 64 { self.mask = 0; } else { self.mask <<= shift as usize; }
            self.mask |= 1;
            self.highest = counter;
            return true;
        }
        if counter == self.highest { return false; }
        let behind = self.highest - counter;
        if behind >= 64 { return false; }
        let bit = 1u64 << behind as usize;
        if (self.mask & bit) != 0 { return false; }
        self.mask |= bit;
        true
    }

    pub fn zero(&mut self) { self.highest = 0; self.mask = 0; }
}

// --- CipherState ---

#[derive(Clone)]
pub struct CipherState { pub key: [u8; 32], pub counter: u64 }

impl CipherState {
    pub fn new() -> Self { Self { key: [0; 32], counter: 0 } }

    pub fn seal(&mut self, out: &mut [u8], plaintext: &[u8], ad: &[u8]) -> Result<()> {
        if self.counter >= REKEY_AFTER_MESSAGES { return Err(TransportError::RekeyRequired); }
        if out.len() < plaintext.len() + 16 { return Err(TransportError::OutOfRange); }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let nonce_bytes = noise::transport_nonce(self.counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, Payload { msg: plaintext, aad: ad })
            .map_err(|_| TransportError::DecryptFailed)?;
        out[..ct.len()].copy_from_slice(&ct);
        self.counter += 1;
        Ok(())
    }

    pub fn zero(&mut self) { self.key = [0; 32]; self.counter = 0; }
}

// --- RecvState ---

#[derive(Clone)]
pub struct RecvState { pub key: [u8; 32], pub window: ReplayWindow }

impl RecvState {
    pub fn new() -> Self { Self { key: [0; 32], window: ReplayWindow::new() } }

    pub fn open(&mut self, out: &mut [u8], ad: &[u8], ct: &[u8], counter: u64) -> Result<usize> {
        if ct.len() < 16 { return Err(TransportError::DecryptFailed); }
        let pt_len = ct.len() - 16;
        if out.len() < pt_len { return Err(TransportError::OutOfRange); }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let nonce_bytes = noise::transport_nonce(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher.decrypt(nonce, Payload { msg: ct, aad: ad })
            .map_err(|_| TransportError::DecryptFailed)?;
        if !self.window.check(counter) { return Err(TransportError::Replay); }
        out[..pt.len()].copy_from_slice(&pt);
        Ok(pt_len)
    }

    pub fn zero(&mut self) { self.key = [0; 32]; self.window.zero(); }
}

// --- Session ---

#[derive(Clone)]
pub struct Session {
    pub local_index: u32,
    pub peer_index: u32,
    pub send: CipherState,
    pub recv: RecvState,
    pub handshake_hash: [u8; 32],
    pub key_epoch_ms: u64,
    pub bound: bool,
    pub in_use: bool,
}

impl Session {
    pub fn new() -> Self {
        Self {
            local_index: 0, peer_index: 0,
            send: CipherState::new(), recv: RecvState::new(),
            handshake_hash: [0; 32], key_epoch_ms: 0,
            bound: false, in_use: false,
        }
    }

    pub fn due_for_rekey(&self, now_ms: u64) -> bool {
        self.send.counter >= REKEY_AFTER_MESSAGES
            || now_ms >= self.key_epoch_ms + REKEY_AFTER_MS
    }

    pub fn seal(&mut self, out: &mut [u8], plaintext: &[u8]) -> Result<usize> {
        let total = HEADER_SIZE + plaintext.len() + 16;
        if out.len() < total { return Err(TransportError::OutOfRange); }
        let mut header = [0u8; HEADER_SIZE];
        header[0] = MSG_TYPE_TRANSPORT;
        header[4..8].copy_from_slice(&self.peer_index.to_be_bytes());
        header[8..16].copy_from_slice(&self.send.counter.to_be_bytes());
        self.send.seal(&mut out[HEADER_SIZE..total], plaintext, &header)?;
        out[..HEADER_SIZE].copy_from_slice(&header);
        Ok(total)
    }

    pub fn open(&mut self, packet: &[u8], hdr_counter: u64, out: &mut [u8]) -> Result<usize> {
        if packet.len() < HEADER_SIZE { return Err(TransportError::OutOfRange); }
        self.recv.open(out, &packet[..HEADER_SIZE], &packet[HEADER_SIZE..], hdr_counter)
    }

    pub fn rotate(&mut self, send_key: [u8; 32], recv_key: [u8; 32],
                  handshake_hash: [u8; 32], now_ms: u64) {
        self.send.zero();
        self.recv.zero();
        self.send.key = send_key;
        self.recv.key = recv_key;
        self.handshake_hash = handshake_hash;
        self.key_epoch_ms = now_ms;
    }
}

// --- SessionTable ---

pub struct SessionTable { slots: [Session; MAX_SESSIONS] }

impl SessionTable {
    pub fn new() -> Self { Self { slots: std::array::from_fn(|_| Session::new()) } }

    pub fn lookup(&mut self, local_index: u32) -> Option<&mut Session> {
        if (local_index as usize) >= MAX_SESSIONS { return None; }
        let slot = &mut self.slots[local_index as usize];
        if !slot.in_use { return None; }
        Some(slot)
    }

    pub fn lookup_immut(&self, local_index: u32) -> Option<&Session> {
        if (local_index as usize) >= MAX_SESSIONS { return None; }
        let slot = &self.slots[local_index as usize];
        if !slot.in_use { return None; }
        Some(slot)
    }

    pub fn admit(&mut self, local_index: u32, peer_index: u32,
                 send_key: [u8; 32], recv_key: [u8; 32],
                 handshake_hash: [u8; 32], now_ms: u64) -> Result<()> {
        if (local_index as usize) >= MAX_SESSIONS { return Err(TransportError::OutOfRange); }
        let slot = &mut self.slots[local_index as usize];
        if slot.in_use { return Err(TransportError::SlotFull); }
        slot.local_index = local_index;
        slot.peer_index = peer_index;
        slot.send.zero(); slot.recv.zero();
        slot.send.key = send_key; slot.recv.key = recv_key;
        slot.handshake_hash = handshake_hash;
        slot.key_epoch_ms = now_ms;
        slot.bound = false; slot.in_use = true;
        Ok(())
    }

    pub fn release(&mut self, local_index: u32) {
        if (local_index as usize) >= MAX_SESSIONS { return; }
        let slot = &mut self.slots[local_index as usize];
        slot.send.zero(); slot.recv.zero();
        slot.handshake_hash = [0; 32];
        slot.bound = false; slot.in_use = false;
    }
}
