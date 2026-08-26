//! Bolina protocol head (Rust reference candidate).
//! Plan: ~/.opencrabs/projects/bolina/rust-port-huntley-plan.md
//! Baseline: zig main @ 1b88522 · Crypto fork: D-096-A · Waves W0-W6.
//!
//! Rules: single-threaded poll model only (no async runtimes until post-parity
//! review); bytes are built explicitly field-by-field (no struct-to-bytes);
//! every module lands WITH its stage-2 contract sheet first.
#![deny(warnings)]
#![forbid(unsafe_code)]

/// RFC KAT suite target (W1). D-096-A: audited crates, versions pinned.
pub mod crypto;

/// Wire codec against frozen vectors byte-a-byte incl. negatives (W2).
pub mod codec;

/// Intent table + durable grant ledger, flock via seam analog (W3).
pub mod state;

/// Noise_IK transport + mutual binding BE-TR-01 (W4, live-interop gate).
pub mod transport;

/// Daemon + HTTP control plane /v1 (W5).
pub mod daemon;

/// CA CLI + node key material, cross-verified with the Zig verifier (W6).
pub mod ca;
