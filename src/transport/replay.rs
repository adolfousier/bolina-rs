//! W9 replay: sliding-window anti-replay filter (replay.zig port).
//!
//! RFC 6479 sliding bitmap at 1024 bits. Zero-heap, caller-owned.
//! BE-TR-03: window MUST be at least 1024 counters wide.

pub const WINDOW_BITS: usize = 1024;
pub const WORD_BITS: usize = 64;
pub const WINDOW_WORDS: usize = WINDOW_BITS / WORD_BITS; // 16

pub struct ReplayWindow {
    window: [u64; WINDOW_WORDS],
    largest: u64,
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            window: [0u64; WINDOW_WORDS],
            largest: 0,
            initialized: false,
        }
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a counter against the window. Returns true for fresh,
    /// false for replay or stale.
    pub fn check(&mut self, counter: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.largest = counter;
            self.window[0] |= 1;
            return true;
        }

        if counter > self.largest {
            let shift = counter - self.largest;
            shift_left(&mut self.window, shift);
            self.largest = counter;
            self.window[0] |= 1;
            return true;
        }

        let diff = self.largest - counter;
        if diff >= WINDOW_BITS as u64 {
            return false;
        }
        let w = (diff / WORD_BITS as u64) as usize;
        let b = (diff % WORD_BITS as u64) as u32;
        let mask: u64 = 1u64 << b;
        if (self.window[w] & mask) != 0 {
            return false; // replay
        }
        self.window[w] |= mask;
        true
    }
}

fn shift_left(win: &mut [u64; WINDOW_WORDS], shift: u64) {
    if shift >= WINDOW_BITS as u64 {
        *win = [0u64; WINDOW_WORDS];
        return;
    }
    let word_shift = (shift / WORD_BITS as u64) as usize;
    let bit_shift = (shift % WORD_BITS as u64) as u32;

    let mut w = WINDOW_WORDS;
    while w > 0 {
        w -= 1;
        let mut v: u64 = 0;
        if bit_shift == 0 {
            if w >= word_shift {
                v = win[w - word_shift];
            }
        } else {
            if w >= word_shift {
                v = win[w - word_shift] << bit_shift;
            }
            if w >= word_shift + 1 {
                v |= win[w - word_shift - 1] >> (WORD_BITS as u32 - bit_shift);
            }
        }
        win[w] = v;
    }
}
