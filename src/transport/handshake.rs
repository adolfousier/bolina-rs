//! handshake.rs — live Noise_IK responder layer (W10).
//! Sheet: specs/handshake.md - Zig: src/handshake.zig (75 lines).
//!
//! BE-SESS-02 single-commit: the session table is mutated in EXACTLY one
//! place - the commit block after responder.finalize(). Every failure path
//! returns BEFORE it; a failed handshake leaves zero half-session state.
//!
//! Ordering inside process_datagram (handshake.zig:50-63): type/length check
//! -> table capacity check -> full Noise verify (mac1 + decrypt) -> build
//! response -> send (exact-length or SendFailed) -> finalize -> commit.
//!
//! The Zig processDatagram takes now_ms and ignores it (timestamp replay is
//! session-layer policy, SPEC 2.2); the Rust head drops the param.

use super::noise::{KeyPair, MSG1_SIZE, MSG2_SIZE, Responder};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// handshake.zig:25 - the RESPONDER accept table (distinct from the session
/// table's larger transport capacity; do not unify without a decision).
pub const MAX_SESSIONS: usize = 16;

/// handshake.zig:34 - D-049: distinct outcomes stay distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    NotInitiation,
    TableFull,
    Refused,
    SendFailed,
}

/// handshake.zig:27-33 - peer_static is the INITIATOR static recovered from
/// IK, not a config value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub peer_static: [u8; 32],
}

/// Commit-only table: capacity checked BEFORE any crypto work (fail fast),
/// mutated only in the commit block.
pub struct Table {
    pub slots: [Option<Session>; MAX_SESSIONS],
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub fn new() -> Self {
        Self { slots: Default::default() }
    }

    pub fn has_free(&self) -> bool {
        self.slots.iter().any(|s| s.is_none())
    }

    fn commit(&mut self, session: Session) -> usize {
        let slot = self.slots.iter().position(|s| s.is_none()).expect("capacity checked before");
        self.slots[slot] = Some(session);
        slot
    }
}

/// processDatagram (handshake.zig:48). The `send` closure plays sendto:
/// exact-length success is `Ok(())`, anything else is SendFailed - and a
/// send failure ABORTS before finalize/commit (no half-session state).
///
/// `own_dh` = responder X25519 static; `own_sig_pub` = Ed25519 public used
/// for mac1. Phase C: mac2 cookie answered ZERO (handshake.zig:11-14).
pub fn process_datagram(
    table: &mut Table,
    datagram: &[u8],
    own_dh_secret: [u8; 32],
    own_sig_pub: &[u8; 32],
    send: impl FnOnce(&[u8]) -> Result<(), ()>,
) -> Result<usize, HandshakeError> {
    // 1. type/length check
    if datagram.len() != MSG1_SIZE || datagram[0] != 1 {
        return Err(HandshakeError::NotInitiation);
    }
    // 2. table capacity check (before crypto)
    if !table.has_free() {
        return Err(HandshakeError::TableFull);
    }
    // 3. full Noise verify: mac1 + decrypt (readInitiation)
    let mut responder = Responder::new(KeyPair { secret: own_dh_secret, public: x25519(own_dh_secret, X25519_BASEPOINT_BYTES) });
    let msg1: [u8; MSG1_SIZE] = datagram.try_into().map_err(|_| HandshakeError::NotInitiation)?;
    let info = responder.read_initiation(&msg1, own_sig_pub).map_err(|_| HandshakeError::Refused)?;

    // 4. build response (zero cookie, phase C)
    let mut out = [0u8; MSG2_SIZE];
    responder
        .write_response(&mut out, 0, info.sender_index, own_sig_pub, &[0u8; 16])
        .map_err(|_| HandshakeError::Refused)?;

    // 5. send exact-length; failure aborts BEFORE finalize/commit
    send(&out).map_err(|_| HandshakeError::SendFailed)?;

    // 6. finalize -> THE single commit block (BE-SESS-02)
    let result = responder.finalize();
    let session = Session {
        send_key: result.send_key,
        recv_key: result.recv_key,
        handshake_hash: result.handshake_hash,
        peer_static: info.initiator_static_pub,
    };
    Ok(table.commit(session))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_send(_: &[u8]) -> Result<(), ()> { Ok(()) }
    fn fail_send(_: &[u8]) -> Result<(), ()> { Err(()) }

    /// wrong type byte AND wrong length both refuse as NotInitiation, before
    /// any capacity/crypto work.
    #[test]
    fn se_02_not_initiation_distinct() {
        let mut t = Table::new();
        assert_eq!(
            process_datagram(&mut t, &[2u8; MSG1_SIZE], [1; 32], &[2; 32], ok_send),
            Err(HandshakeError::NotInitiation)
        );
        assert_eq!(
            process_datagram(&mut t, &[1u8; 10], [1; 32], &[2; 32], ok_send),
            Err(HandshakeError::NotInitiation)
        );
        assert!(t.slots.iter().all(|s| s.is_none()));
    }

    /// capacity refused BEFORE crypto; distinct from Refused.
    #[test]
    fn se_02_table_full_before_crypto() {
        let mut t = Table::new();
        for s in t.slots.iter_mut() {
            *s = Some(Session { send_key: [0; 32], recv_key: [0; 32], handshake_hash: [0; 32], peer_static: [0; 32] });
        }
        assert_eq!(
            process_datagram(&mut t, &[1u8; MSG1_SIZE], [1; 32], &[2; 32], ok_send),
            Err(HandshakeError::TableFull)
        );
    }

    /// SendFailed leaves ZERO half-session state (ordering: send precedes
    /// finalize/commit). Uses a REAL valid initiation so the failure lands
    /// exactly at the send step, not at verify.
    #[test]
    fn se_02_send_failed_no_half_session() {
        use crate::transport::noise::{Initiator, KeyPair as NKeyPair};
        use rand_core::{OsRng, RngCore};
        use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

        let mut isec = [0u8; 32];
        OsRng.fill_bytes(&mut isec);
        let rsec = [7u8; 32];
        let rpub = x25519(rsec, X25519_BASEPOINT_BYTES);
        let mut init = Initiator::new(NKeyPair { secret: isec, public: x25519(isec, X25519_BASEPOINT_BYTES) }, rpub);
        let mut msg1 = [0u8; MSG1_SIZE];
        init.write_initiation(&mut msg1, 1, 12345, &[2; 32], &[0u8; 16]).unwrap();

        let mut t = Table::new();
        assert_eq!(
            process_datagram(&mut t, &msg1, rsec, &[2; 32], fail_send),
            Err(HandshakeError::SendFailed)
        );
        assert!(t.slots.iter().all(|s| s.is_none()));
    }

    /// Full happy path with a REAL initiation: slot committed, session
    /// carries the IK-recovered initiator static.
    #[test]
    fn se_02_happy_path_commits_once() {
        use crate::transport::noise::{Initiator, KeyPair as NKeyPair};
        use rand_core::{OsRng, RngCore};
        use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

        let mut isec = [0u8; 32];
        OsRng.fill_bytes(&mut isec);
        let rsec = [9u8; 32];
        let rpub = x25519(rsec, X25519_BASEPOINT_BYTES);
        let mut init = Initiator::new(NKeyPair { secret: isec, public: x25519(isec, X25519_BASEPOINT_BYTES) }, rpub);
        let mut msg1 = [0u8; MSG1_SIZE];
        init.write_initiation(&mut msg1, 3, 77, &[4; 32], &[0u8; 16]).unwrap();

        let mut t = Table::new();
        let slot = process_datagram(&mut t, &msg1, rsec, &[4; 32], ok_send).unwrap();
        assert_eq!(slot, 0);
        let s = t.slots[0].unwrap();
        assert_eq!(s.peer_static, x25519(isec, X25519_BASEPOINT_BYTES));
        // keys derived from the real exchange, never zero (D-018 spirit)
        assert_ne!(s.send_key, [0u8; 32]);
        assert_ne!(s.recv_key, [0u8; 32]);
        assert_ne!(s.handshake_hash, [0u8; 32]);
    }
}
