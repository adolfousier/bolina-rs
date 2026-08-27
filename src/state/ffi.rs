//! Flat flock seam (W3). The ONE module where unsafe lives; mirrors the Zig
//! flat-libc idiom (src/grant_ledger.zig MD3 block). LOCK_EX|LOCK_NB = 2|4,
//! identical values macOS/Linux. Everything else in this crate stays safe.
#![allow(unsafe_code)]

use std::fs::File;
use std::os::fd::AsRawFd;

pub const LOCK_EX: i32 = 2;
pub const LOCK_NB: i32 = 4;

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

/// Try a non-blocking exclusive lock. true = acquired; false = held elsewhere.
pub fn flock_exclusive_nb(f: &File) -> bool {
    unsafe { flock(f.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
}
