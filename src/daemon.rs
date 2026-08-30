//! daemon: single-threaded node core
//!
//! Multiplexes wire UDP + optional TCP control via one poll() loop.
//! Zero threads (E4 rule). Owns all state.
//!
//! Wiring order (main.rs reads):
//!   keys::load_or_generate
//!   -> ledger::init_durable
//!   -> dispatch::init
//!   -> Daemon struct (static storage for stable pointers)
//!   -> optional control::attach via BOLINA_CONTROL env
//!
//! handleTransport path:
//!   mac1 gate FIRST (3 rejection sites before ANY X25519)
//!   -> session lookup
//!   -> if !bound: binding frame verify (F1 signature, cert kex must EQUAL handshake static)
//!   -> then envelopes
//!
//! Response type-2 index layout (SPEC 4.1a, fix e4fd0d4):
//!   offset 4 = responder's sender_index (local slot)
//!   offset 8 = echo of initiator's announced index
//! The kill-proof test (0xA70F1E) is INHERITED MANDATORY - this bug survived 177 mutants.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::state::{ledger, Table};
use crate::transport::mac1;

// Static shutdown flag for signal handler
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Daemon core: holds all state, runs the poll loop
pub struct Daemon {
    pub keys: Keys,
    pub ledger: Option<ledger::GrantLedger>,
    pub intents: Table,
    pub sessions: SessionTable,
    pub handshake: HandshakeServer,
    pub control: Option<ControlPlane>,
    pub bind_addr: SocketAddr,
    pub started: Instant,
}

impl Daemon {
    pub fn new(bind: SocketAddr, keys: Keys) -> Self {
        Self {
            keys,
            ledger: None,
            intents: Table::new(),
            sessions: SessionTable::new(),
            handshake: HandshakeServer::new(),
            control: None,
            bind_addr: bind,
            started: Instant::now(),
        }
    }

    pub fn attach_ledger(&mut self, path: &std::path::Path) -> Result<(), String> {
        self.ledger = Some(ledger::GrantLedger::open(path).map_err(|e| format!("{:?}", e))?);
        Ok(())
    }

    pub fn attach_control(&mut self, addr: SocketAddr) -> Result<(), String> {
        self.control = Some(ControlPlane::new(addr)?);
        Ok(())
    }

    /// Main poll loop: UDP wire + optional TCP control, single-threaded
    pub fn run_loop(&mut self) -> Result<(), String> {
        let udp_sock = std::net::UdpSocket::bind(self.bind_addr).map_err(|e| e.to_string())?;
        udp_sock.set_nonblocking(true).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 4096];

        loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }

            // UDP recv
            match udp_sock.recv_from(&mut buf) {
                Ok((len, src)) => {
                    self.handle_datagram(&buf[..len], src);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No packet, continue
                }
                Err(e) => return Err(format!("recv_from: {}", e)),
            }

            // Control plane (if attached)
            if let Some(ref mut ctrl) = self.control {
                ctrl.poll_tick(&mut self.intents, &self.ledger)?;
            }

            // Small sleep to avoid busy-wait (10ms)
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Drain: flush ledger if attached
        if let Some(ref mut _ledger) = self.ledger {
            // TODO: add sync method to ledger
        }

        Ok(())
    }

    /// Process one inbound datagram
    pub fn handle_datagram(&mut self, pkt: &[u8], src: SocketAddr) {
        if pkt.is_empty() {
            return;
        }

        let msg_type = pkt[0];
        match msg_type {
            1 => self.handle_handshake(pkt, src),
            4 => self.handle_transport(pkt, src),
            5 | 6 => {
                // Relay role-gated: drop if no RelayServe attached
                // (sender-gate inheritance from relay_serve.md)
                // For now: silent drop fail-closed
            }
            _ => {
                // Unknown type: drop
            }
        }
    }

    fn handle_handshake(&mut self, pkt: &[u8], _src: SocketAddr) {
        // mac1 gate FIRST (3 rejection sites before ANY X25519)
        if pkt.len() < 144 {
            return;
        }
        let mac1_bytes: &[u8; 16] = pkt[112..128].try_into().unwrap();
        let mac1_ok = mac1::verify_mac1(&self.keys.sig_pub, &pkt[..112], mac1_bytes);
        if !mac1_ok {
            return; // Mac1Failed - no X25519 work
        }

        // Full Noise_IK processing
        match self.handshake.process_initiation(&pkt, &self.keys) {
            Ok((session, response)) => {
                // Send response (type-2 layout per SPEC 4.1a)
                // offset 4 = our sender_index, offset 8 = echo of their announced
                let _ = response; // TODO: send via UDP
                let _ = session;
            }
            Err(_) => {
                // Handshake failed: drop
            }
        }
    }

    fn handle_transport(&mut self, pkt: &[u8], _src: SocketAddr) {
        // type-4: binding or envelope
        if pkt.len() < 16 {
            return;
        }

        // Header: type(1) + reserved(3) + receiver_index(4) + counter(8)
        let receiver_idx = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);

        // Session lookup by receiver index
        match self.sessions.lookup(receiver_idx) {
            Some(session) => {
                if !session.bound {
                    // First packet: binding frame
                    // Verify F1 signature + cert kex must EQUAL handshake static
                    // (KexPubkeyMismatch if not)
                    // TODO: parse binding frame, verify, set bound=true
                } else {
                    // Envelope processing
                    // Decrypt with session keys, parse, dispatch
                    // TODO
                }
            }
            None => {
                // No session: drop
            }
        }
    }
}

/// Signal handler: set shutdown flag
pub fn install_shutdown_handler() {
    ctrlc::set_handler(move || {
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .ok();
}

/// Node keys (load_or_generate from main.rs)
pub struct Keys {
    pub kex_secret: [u8; 32],
    pub kex_pub: [u8; 32],
    pub sig_secret: [u8; 32],
    pub sig_pub: [u8; 32],
}

impl Keys {
    pub fn load_or_generate(_dir: &str) -> Result<Self, String> {
        // Read or generate X25519 + Ed25519 keypairs
        // 0600 files, 0700 dir
        // TODO: implement via keys.md contract
        Err("not implemented".into())
    }
}

/// Session table (indexed by local slot)
pub struct SessionTable {
    sessions: Vec<Session>,
}

impl SessionTable {
    pub fn new() -> Self {
        Self { sessions: Vec::new() }
    }

    pub fn lookup(&self, idx: u32) -> Option<&Session> {
        self.sessions.get(idx as usize)
    }

    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }
}

pub struct Session {
    pub bound: bool,
    pub peer_kex: [u8; 32],
    pub c1: [u8; 32],
    pub c2: [u8; 32],
    pub nonce_in: u64,
    pub nonce_out: u64,
}

/// Handshake server (responder side)
pub struct HandshakeServer {
    // State machine per-initiation
}

impl HandshakeServer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn process_initiation(
        &self,
        _msg1: &[u8],
        _keys: &Keys,
    ) -> Result<(Session, Vec<u8>), String> {
        // Noise_IK responder flow
        // TODO: implement via transport/noise.md contract
        Err("not implemented".into())
    }
}

/// Optional control plane (TCP HTTP)
#[allow(dead_code)]
pub struct ControlPlane {
    addr: SocketAddr,
}

impl ControlPlane {
    pub fn new(addr: SocketAddr) -> Result<Self, String> {
        Ok(Self { addr })
    }

    pub fn poll_tick(
        &mut self,
        _intents: &mut Table,
        _ledger: &Option<ledger::GrantLedger>,
    ) -> Result<(), String> {
        // HTTP accept + route via control_api
        // TODO: implement via control_api.md contract
        Ok(())
    }
}
