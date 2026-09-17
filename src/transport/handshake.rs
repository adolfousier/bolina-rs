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

use super::noise::{KeyPair, Responder, MSG1_SIZE, MSG2_SIZE};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// handshake.zig:25 - the RESPONDER accept table (distinct from the session
/// table's larger transport capacity; do not unify without a decision).
pub const MAX_SESSIONS: usize = 16;

/// Idle-timeout horizon for handshake slot release (candidate-seal 2026-09-15,
/// docs/handshake-slot-release-design.md §4). Deliberately equal to the
/// system's own staleness horizon T_PENDING_MS (state/intent.rs:5, Zig
/// intent.zig:45 BE-GRANT-06a): a session silent longer than the horizon the
/// system already uses to decide a lane is stuck is, by the system's own
/// clock, dead. Inheriting an existing constant's value keeps the lifetime
/// claim reviewable against a documented number instead of a new magic one.
pub const T_HS_IDLE_MS: u64 = 900_000;

/// handshake.zig:34 - D-049: distinct outcomes stay distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    NotInitiation,
    TableFull,
    Refused,
    SendFailed,
}

/// handshake.zig:27-33 - peer_static is the INITIATOR static recovered from
/// IK, not a config value. created_ms tracks when the session was committed
/// for stale-release policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub peer_static: [u8; 32],
    pub created_ms: u64,
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
        Self {
            slots: Default::default(),
        }
    }

    pub fn has_free(&self) -> bool {
        self.slots.iter().any(|s| s.is_none())
    }

    fn commit(&mut self, session: Session) -> usize {
        let slot = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .expect("capacity checked before");
        self.slots[slot] = Some(session);
        slot
    }

    /// Release a single slot by index. Zeroizes the session before
    /// dropping (D-018 key hygiene). No-op if index is out of range
    /// or the slot is already free.
    pub fn release_slot(&mut self, index: usize) {
        if index >= MAX_SESSIONS {
            return;
        }
        if let Some(ref mut s) = self.slots[index] {
            s.send_key = [0; 32];
            s.recv_key = [0; 32];
            s.handshake_hash = [0; 32];
            s.peer_static = [0; 32];
            s.created_ms = 0;
        }
        self.slots[index] = None;
    }

    /// Release all slots older than `timeout_ms` from `now_ms`. Returns the
    /// FREED INDICES (the daemon mirrors each release into the session table
    /// and peer_static - design §4 step 2, one shared index space).
    /// Zeroizes keys before dropping (D-018).
    pub fn release_stale(&mut self, now_ms: u64, timeout_ms: u64) -> Vec<usize> {
        let mut freed = Vec::new();
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if let Some(ref mut s) = slot {
                if now_ms.saturating_sub(s.created_ms) > timeout_ms {
                    // zeroize before drop (D-018)
                    s.send_key = [0; 32];
                    s.recv_key = [0; 32];
                    s.handshake_hash = [0; 32];
                    s.peer_static = [0; 32];
                    s.created_ms = 0;
                    *slot = None;
                    freed.push(idx);
                }
            }
        }
        freed
    }
}

/// processDatagram (handshake.zig:48). The `send` closure plays sendto:
/// exact-length success is `Ok(())`, anything else is SendFailed - and a
/// send failure ABORTS before finalize/commit (no half-session state).
///
/// `own_dh` = responder X25519 static; `own_sig_pub` = Ed25519 public used
/// for mac1. Phase C: mac2 cookie answered ZERO (handshake.zig:11-14).
/// `now_ms` = current time for session timestamp (stale-release policy).
pub fn process_datagram(
    table: &mut Table,
    datagram: &[u8],
    own_dh_secret: [u8; 32],
    own_sig_pub: &[u8; 32],
    send: impl FnOnce(&[u8]) -> Result<(), ()>,
    now_ms: u64,
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
    let mut responder = Responder::new(KeyPair {
        secret: own_dh_secret,
        public: x25519(own_dh_secret, X25519_BASEPOINT_BYTES),
    });
    let msg1: [u8; MSG1_SIZE] = datagram
        .try_into()
        .map_err(|_| HandshakeError::NotInitiation)?;
    let info = responder
        .read_initiation(&msg1, own_sig_pub)
        .map_err(|_| HandshakeError::Refused)?;

    // 4. build response (zero cookie, phase C)
    // Responder sender_index = the slot this handshake will commit to
    // (Zig handshake.zig:61 passes session_count, the next free slot).
    // We find the free position before write_response so the peer reads
    // the correct index from msg2; commit() below re-derives the same
    // position (first None), so they agree.
    let responder_index = table
        .slots
        .iter()
        .position(|s| s.is_none())
        .expect("capacity checked before");
    let mut out = [0u8; MSG2_SIZE];
    responder
        .write_response(
            &mut out,
            responder_index as u32,
            info.sender_index,
            own_sig_pub,
            &[0u8; 16],
        )
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
        created_ms: now_ms,
    };
    Ok(table.commit(session))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_send(_: &[u8]) -> Result<(), ()> {
        Ok(())
    }
    fn fail_send(_: &[u8]) -> Result<(), ()> {
        Err(())
    }

    /// wrong type byte AND wrong length both refuse as NotInitiation, before
    /// any capacity/crypto work.
    #[test]
    fn se_02_not_initiation_distinct() {
        let mut t = Table::new();
        assert_eq!(
            process_datagram(&mut t, &[2u8; MSG1_SIZE], [1; 32], &[2; 32], ok_send, 0),
            Err(HandshakeError::NotInitiation)
        );
        assert_eq!(
            process_datagram(&mut t, &[1u8; 10], [1; 32], &[2; 32], ok_send, 0),
            Err(HandshakeError::NotInitiation)
        );
        assert!(t.slots.iter().all(|s| s.is_none()));
    }

    /// capacity refused BEFORE crypto; distinct from Refused.
    #[test]
    fn se_02_table_full_before_crypto() {
        let mut t = Table::new();
        for s in t.slots.iter_mut() {
            *s = Some(Session {
                send_key: [0; 32],
                recv_key: [0; 32],
                handshake_hash: [0; 32],
                peer_static: [0; 32],
                created_ms: 0,
            });
        }
        assert_eq!(
            process_datagram(&mut t, &[1u8; MSG1_SIZE], [1; 32], &[2; 32], ok_send, 0),
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
        let mut init = Initiator::new(
            NKeyPair {
                secret: isec,
                public: x25519(isec, X25519_BASEPOINT_BYTES),
            },
            rpub,
        );
        let mut msg1 = [0u8; MSG1_SIZE];
        init.write_initiation(&mut msg1, 1, 12345, &[2; 32], &[0u8; 16])
            .unwrap();

        let mut t = Table::new();
        assert_eq!(
            process_datagram(&mut t, &msg1, rsec, &[2; 32], fail_send, 0),
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
        let mut init = Initiator::new(
            NKeyPair {
                secret: isec,
                public: x25519(isec, X25519_BASEPOINT_BYTES),
            },
            rpub,
        );
        let mut msg1 = [0u8; MSG1_SIZE];
        init.write_initiation(&mut msg1, 3, 77, &[4; 32], &[0u8; 16])
            .unwrap();

        let mut t = Table::new();
        let slot = process_datagram(&mut t, &msg1, rsec, &[4; 32], ok_send, 0).unwrap();
        assert_eq!(slot, 0);
        let s = t.slots[0].unwrap();
        assert_eq!(s.peer_static, x25519(isec, X25519_BASEPOINT_BYTES));
        // keys derived from the real exchange, never zero (D-018 spirit)
        assert_ne!(s.send_key, [0u8; 32]);
        assert_ne!(s.recv_key, [0u8; 32]);
        assert_ne!(s.handshake_hash, [0u8; 32]);
    }

    /// release_slot frees a single slot and zeroizes keys.
    #[test]
    fn se_02_release_slot_frees_and_zeroizes() {
        let mut t = Table::new();
        // Fill slot 0
        t.slots[0] = Some(Session {
            send_key: [1; 32],
            recv_key: [2; 32],
            handshake_hash: [3; 32],
            peer_static: [4; 32],
            created_ms: 1000,
        });
        assert!(t.slots[0].is_some());
        // Release it
        t.release_slot(0);
        assert!(t.slots[0].is_none());
        // Double release is safe (no-op)
        t.release_slot(0);
        assert!(t.slots[0].is_none());
        // Out-of-range is safe
        t.release_slot(MAX_SESSIONS + 1);
    }

    /// release_stale frees only slots older than timeout.
    #[test]
    fn se_02_release_stale_frees_old_slots() {
        let mut t = Table::new();
        // Slot 0: created at t=1000
        t.slots[0] = Some(Session {
            send_key: [1; 32],
            recv_key: [2; 32],
            handshake_hash: [3; 32],
            peer_static: [4; 32],
            created_ms: 1000,
        });
        // Slot 1: created at t=5000
        t.slots[1] = Some(Session {
            send_key: [5; 32],
            recv_key: [6; 32],
            handshake_hash: [7; 32],
            peer_static: [8; 32],
            created_ms: 5000,
        });
        // Slot 2: free (None)
        assert!(t.slots[2].is_none());

        // At now=6000, timeout=2000: slot 0 is stale (6000-1000=5000 > 2000),
        // slot 1 is fresh (6000-5000=1000 < 2000)
        let released = t.release_stale(6000, 2000);
        assert_eq!(released, vec![0]); // freed INDEX, not just count
        assert!(t.slots[0].is_none()); // released
        assert!(t.slots[1].is_some()); // kept
        assert!(t.slots[2].is_none()); // was already free

        // At now=8000, timeout=2000: slot 1 is now stale (8000-5000=3000 > 2000)
        let released = t.release_stale(8000, 2000);
        assert_eq!(released, vec![1]);
        assert!(t.slots[1].is_none());
    }

    /// release_stale with timeout=0 releases nothing (nothing is older than now).
    #[test]
    fn se_02_release_stale_zero_timeout_releases_nothing() {
        let mut t = Table::new();
        t.slots[0] = Some(Session {
            send_key: [1; 32],
            recv_key: [2; 32],
            handshake_hash: [3; 32],
            peer_static: [4; 32],
            created_ms: 1000,
        });
        // timeout=0 means nothing is older than now-0=now
        let released = t.release_stale(1000, 0);
        assert!(released.is_empty());
        assert!(t.slots[0].is_some());
    }

    fn literal_session(created_ms: u64) -> Session {
        Session {
            send_key: [1; 32],
            recv_key: [2; 32],
            handshake_hash: [3; 32],
            peer_static: [4; 32],
            created_ms,
        }
    }

    /// Design §5 "Unit, table", fake clock, literal values (D-027):
    /// 16 commits -> 17th TableFull; advance past the idle horizon,
    /// release_stale frees EXACTLY the expired; the 17th now commits.
    /// T_HS_IDLE_MS = 900_000 is asserted as the literal 900_000 here,
    /// never via the constant (expectation must not share its source).
    #[test]
    fn slot_release_wall_then_recycle_fake_clock() {
        use crate::transport::noise::{Initiator, KeyPair as NKeyPair};
        use rand_core::{OsRng, RngCore};
        use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

        // The horizon IS 900_000 ms - pinned as a literal, design §4.
        assert_eq!(T_HS_IDLE_MS, 900_000);

        let rsec = [11u8; 32];
        let rsig = [12u8; 32];
        let mut t = Table::new();
        // All 16 slots committed at t=1_000_000 (literal clock).
        for slot in t.slots.iter_mut() {
            *slot = Some(literal_session(1_000_000));
        }

        // 17th handshake against the full table: TableFull.
        let msg1 = |sender_index: u32| -> [u8; MSG1_SIZE] {
            let mut isec = [0u8; 32];
            OsRng.fill_bytes(&mut isec);
            let mut init = Initiator::new(
                NKeyPair {
                    secret: isec,
                    public: x25519(isec, X25519_BASEPOINT_BYTES),
                },
                x25519(rsec, X25519_BASEPOINT_BYTES),
            );
            let mut m = [0u8; MSG1_SIZE];
            init.write_initiation(&mut m, sender_index, 1_000_000, &rsig, &[0u8; 16])
                .unwrap();
            m
        };
        assert_eq!(
            process_datagram(&mut t, &msg1(101), rsec, &rsig, ok_send, 1_500_000),
            Err(HandshakeError::TableFull)
        );

        // At exactly the horizon (now - created == 900_000) nothing frees:
        // the comparison is strict > (1_900_000 - 1_000_000 = 900_000).
        let released = t.release_stale(1_900_000, 900_000);
        assert!(released.is_empty());
        assert_eq!(t.slots.iter().filter(|s| s.is_some()).count(), 16);

        // One ms past the horizon: ALL 16 expire, freed indices in order.
        let released = t.release_stale(1_900_001, 900_000);
        assert_eq!(released, (0..16).collect::<Vec<usize>>());
        assert!(t.slots.iter().all(|s| s.is_none()));

        // The 17th handshake now commits, into the first freed slot.
        let slot = process_datagram(&mut t, &msg1(102), rsec, &rsig, ok_send, 1_900_001).unwrap();
        assert_eq!(slot, 0);
    }

    /// Mixed ages: release_stale frees EXACTLY the expired, keeps the fresh,
    /// and the freed index list is the mirror-cleanup input (design §4.2).
    #[test]
    fn slot_release_mixed_ages_frees_exactly_expired() {
        let mut t = Table::new();
        t.slots[1] = Some(literal_session(100_000)); // age at now: 900_001 -> stale
        t.slots[5] = Some(literal_session(100_500)); // age at now: 899_501 -> fresh
        t.slots[9] = Some(literal_session(50_000)); // age at now: 950_001 -> stale
        let released = t.release_stale(1_000_001, 900_000);
        assert_eq!(released, vec![1, 9]);
        assert!(t.slots[1].is_none());
        assert!(t.slots[5].is_some());
        assert!(t.slots[9].is_none());
    }
}
