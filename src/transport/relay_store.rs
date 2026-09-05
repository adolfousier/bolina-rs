//! W9 relay_store: store-and-forward engine (relay_store.zig port).
//!
//! BE-MESH-03: bounded relay storage with TTL expiry.
//! Storage keys by overlay_addr, not client_index (D-058).

pub const MAX_BODY: usize = 2048;
pub const MAX_PER_RECIPIENT: usize = 64;
pub const MAX_BYTES_PER_RECIPIENT: usize = 4 * 1024 * 1024;
pub const TTL_MS: u64 = 120 * 1000;
pub const MAX_STORED: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    BodyTooLarge,
    RecipientQuota,
    StoreFull,
}

pub struct StoredPacket {
    pub in_use: bool,
    pub sender_index: u32,
    pub recipient_addr: [u8; 16],
    pub body_len: usize,
    pub body: [u8; MAX_BODY],
    pub stored_at_ms: u64,
}

impl Default for StoredPacket {
    fn default() -> Self {
        Self {
            in_use: false,
            sender_index: 0,
            recipient_addr: [0u8; 16],
            body_len: 0,
            body: [0u8; MAX_BODY],
            stored_at_ms: 0,
        }
    }
}

pub struct DrainedPacket<'a> {
    pub sender_index: u32,
    pub body: &'a [u8],
}

pub struct Store {
    pub packets: Vec<StoredPacket>,
    pub count: usize,
    pub refused_quota: u64,
}

impl Store {
    pub fn new() -> Self {
        let mut packets = Vec::with_capacity(MAX_STORED);
        for _ in 0..MAX_STORED {
            packets.push(StoredPacket::default());
        }
        Self { packets, count: 0, refused_quota: 0 }
    }

    pub fn reset(&mut self) {
        for p in &mut self.packets {
            p.in_use = false;
        }
        self.count = 0;
        self.refused_quota = 0;
    }

    pub fn store(
        &mut self,
        recipient_addr: [u8; 16],
        sender_index: u32,
        body: &[u8],
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if body.len() > MAX_BODY {
            return Err(StoreError::BodyTooLarge);
        }
        self.purge_expired(now_ms);
        if self.count >= MAX_STORED {
            self.refused_quota += 1;
            return Err(StoreError::StoreFull);
        }
        let mut recip_count = 0usize;
        let mut recip_bytes = 0usize;
        for p in &self.packets {
            if !p.in_use || p.recipient_addr != recipient_addr {
                continue;
            }
            recip_count += 1;
            recip_bytes += p.body_len;
        }
        if recip_count >= MAX_PER_RECIPIENT || recip_bytes + body.len() > MAX_BYTES_PER_RECIPIENT {
            self.refused_quota += 1;
            return Err(StoreError::RecipientQuota);
        }
        for p in &mut self.packets {
            if p.in_use {
                continue;
            }
            p.in_use = true;
            p.sender_index = sender_index;
            p.recipient_addr = recipient_addr;
            p.body_len = body.len();
            p.body[..body.len()].copy_from_slice(body);
            p.stored_at_ms = now_ms;
            self.count += 1;
            return Ok(());
        }
        self.refused_quota += 1;
        Err(StoreError::StoreFull)
    }

    pub fn drain_next(&mut self, recipient_addr: &[u8; 16], now_ms: u64) -> Option<DrainedPacket<'_>> {
        self.purge_expired(now_ms);
        let mut best: Option<usize> = None;
        for (i, p) in self.packets.iter().enumerate() {
            if !p.in_use || &p.recipient_addr != recipient_addr {
                continue;
            }
            if let Some(b) = best {
                if p.stored_at_ms > self.packets[b].stored_at_ms {
                    continue;
                }
                if p.stored_at_ms == self.packets[b].stored_at_ms && i > b {
                    continue;
                }
            }
            best = Some(i);
        }
        let idx = best?;
        let sender_index = self.packets[idx].sender_index;
        let body_len = self.packets[idx].body_len;
        self.packets[idx].in_use = false;
        self.count -= 1;
        Some(DrainedPacket {
            sender_index,
            body: &self.packets[idx].body[..body_len],
        })
    }

    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let mut purged = 0usize;
        for p in &mut self.packets {
            if !p.in_use {
                continue;
            }
            if now_ms >= p.stored_at_ms && now_ms - p.stored_at_ms >= TTL_MS {
                p.in_use = false;
                self.count -= 1;
                purged += 1;
            }
        }
        purged
    }
}
