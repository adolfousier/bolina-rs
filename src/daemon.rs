//! daemon: single-threaded node core, W12 task-8 wiring.
//!
//! Composes the W2-W11 modules on one poll() loop (E4: zero threads):
//!   mac1 gate -> Noise_IK responder (transport::handshake) -> session admit
//!   -> binding frame (transport::binding, F1 kex==static) -> envelope path:
//!   sig gate FIRST (ladder C declared physics) -> F5 admission
//!   (verify_envelope_admission: parents -> seq -> hash store) -> Dispatch
//!   -> EventRing. Control plane: http_parse -> control_api routes, bearer
//!   token on everything except /healthz (F7).
//!
//! Declared deltas (W12, docs/w12-integration-harness-design.md addendum):
//!   - shipped effect hook is fail-closed: commits consumed-grant durably,
//!     returns Refused, never executes (D-089; effect backend deferred)
//!   - is_revoked hook inert: no revocation source is wired in W12 scope
//!   - Outcome::Effect/Utterance publish no ring event (no such ring tags)
//!   - envelope hash = BLAKE2s-256(full envelope wire); pinned by test
//!   - anchors (BE-HIST-02) are an audit-path record, not an admission
//!     gate: F5 admission deliberately does not consult them

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::{Blake2s256, Digest};

use crate::codec::{self, parse_envelope};
use crate::control::{Connection, ControlPlane};
use crate::control_api::{self, EventRing, EventTag, Metrics, WireCounters, WireRejectClass};
use crate::http_parse::{self, Method};
use crate::keys;
use crate::ledger_envelope;
use crate::state::intent;
use crate::state::ledger::{GrantLedger, GRANT_ID_LEN};
use crate::transport::binding::{self, CertView};
use crate::transport::dispatch::{Dispatch, Hooks, Outcome};
use crate::transport::handshake;
use crate::transport::resolver::Resolver;
use crate::transport::session::{SessionTable, HEADER_SIZE};
use crate::transport::token;
use crate::transport::verify::{
    verify_envelope, verify_envelope_admission, EffectOutcome, SenderTable,
};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn install_shutdown_handler() {
    ctrlc::set_handler(move || {
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .ok();
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// BLAKE2s-256 over the full envelope wire: the ledger identity of an
/// envelope (dup detection + divergence). Pinned by hash_is_blake2s_of_wire.
fn envelope_hash(wire: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(wire);
    h.finalize().into()
}

/// Node core. All state lives here; the poll loop owns the wire socket.
pub struct Daemon {
    pub keys: keys::Keys,
    pub ledger: Option<GrantLedger>,
    pub mem: ledger_envelope::Ledger,
    pub intents: intent::Table,
    pub senders: SenderTable,
    pub resolver: Resolver,
    pub ring: EventRing,
    pub metrics: Metrics,
    pub sessions: SessionTable,
    pub control: Option<ControlPlane>,
    pub token: Option<[u8; token::TOKEN_HEX_LEN]>,
    pub ctl_requests: u64,
    pub ctl_auth_refused: u64,
    pub rejected_total: u64,
    pub wire: WireCounters,
    hs: handshake::Table,
    peer_static: [Option<[u8; 32]>; handshake::MAX_SESSIONS],
    /// sender sig pubkey -> binding cert wire (cert_for_sender source)
    certs: Vec<(Vec<u8>, Vec<u8>)>,
    bind_addr: SocketAddr,
}

impl Daemon {
    pub fn new(bind: SocketAddr, keys: keys::Keys) -> Self {
        let resolver = Resolver::new(&keys.sig_pub());
        Self {
            keys,
            ledger: None,
            mem: ledger_envelope::Ledger::new(),
            intents: intent::Table::new(),
            senders: SenderTable::new(),
            resolver,
            ring: EventRing::new(),
            metrics: Metrics { admitted_total: 0 },
            sessions: SessionTable::new(),
            control: None,
            token: None,
            ctl_requests: 0,
            ctl_auth_refused: 0,
            rejected_total: 0,
            wire: WireCounters::new(),
            hs: handshake::Table::new(),
            peer_static: [None; handshake::MAX_SESSIONS],
            certs: Vec::new(),
            bind_addr: bind,
        }
    }

    pub fn attach_ledger(&mut self, path: &std::path::Path) -> Result<(), String> {
        self.ledger = Some(GrantLedger::open(path).map_err(|e| format!("{e:?}"))?);
        Ok(())
    }

    pub fn attach_control(&mut self, addr: SocketAddr) -> Result<(), String> {
        self.control = Some(ControlPlane::new(addr)?);
        Ok(())
    }

    /// BOLINA_RESOURCES boot seeding: fail-closed node serves only what it
    /// declares (BE-RES-02, Zig main.zig:204 contract). Fatal on refusal.
    /// Test/harness visibility: how many sender certs the binding path stored.
    pub fn sender_cert_count(&self) -> usize {
        self.certs.len()
    }

    /// Test visibility: committed handshake slots (0 = handshake refused).
    pub fn handshake_slots_used(&self) -> usize {
        self.hs.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn add_resource(&mut self, canonical: &str) -> Result<(), String> {
        self.resolver
            .add(canonical.as_bytes())
            .map_err(|e| format!("resource '{canonical}' refused by resolver: {e:?}"))
    }

    pub fn run_loop(&mut self) -> Result<(), String> {
        let udp_sock = UdpSocket::bind(self.bind_addr).map_err(|e| e.to_string())?;
        udp_sock.set_nonblocking(true).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 4096];
        loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            match udp_sock.recv_from(&mut buf) {
                Ok((len, src)) => self.handle_datagram(&buf[..len], src, &udp_sock),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("recv_from: {e}")),
            }
            if self.control.is_some() {
                self.poll_control()?;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Drain: ledger fsyncs per record (T1); nothing buffered to flush.
        Ok(())
    }

    fn poll_control(&mut self) -> Result<(), String> {
        // Split borrows: ControlPlane owns connections; routing mutates the
        // authority state. Destructure so both live at once.
        let Self {
            control,
            intents,
            resolver,
            ring,
            metrics,
            token,
            ctl_requests,
            ctl_auth_refused,
            ..
        } = self;
        let ctrl = control.as_mut().expect("checked caller");
        ctrl.poll_tick()?;
        let now = now_ms();
        for conn in ctrl.clients.iter_mut() {
            if matches!(conn.state, crate::control::ConnState::Writing) {
                *ctl_requests += 1;
                route_http(
                    conn,
                    RouteCtx {
                        intents,
                        resolver,
                        ring,
                        metrics,
                        token: token.as_ref(),
                        auth_refused: ctl_auth_refused,
                        now,
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn handle_datagram(&mut self, pkt: &[u8], src: SocketAddr, sock: &UdpSocket) {
        if pkt.is_empty() {
            return;
        }
        match pkt[0] {
            1 => self.handle_handshake(pkt, src, sock),
            4 => self.handle_transport(pkt),
            // Relay types 5/6: role-gated serving is post-W12 (design section 13)
            _ => {}
        }
    }

    fn handle_handshake(&mut self, pkt: &[u8], src: SocketAddr, sock: &UdpSocket) {
        let sig_pub = self.keys.sig_pub();
        let res = handshake::process_datagram(
            &mut self.hs,
            pkt,
            self.keys.secret_static,
            &sig_pub,
            // exact-length sendto; a failed send aborts BEFORE commit
            |out: &[u8]| sock.send_to(out, src).map(|_| ()).map_err(|_| ()),
            now_ms(),
        );
        if let Ok(slot) = res {
            let Some(s) = self.hs.slots[slot].as_ref() else {
                return;
            };
            let (send_key, recv_key, h, peer) =
                (s.send_key, s.recv_key, s.handshake_hash, s.peer_static);
            if self
                .sessions
                .admit(slot as u32, 0, send_key, recv_key, h, now_ms())
                .is_ok()
            {
                self.peer_static[slot] = Some(peer);
            }
        }
    }

    fn handle_transport(&mut self, pkt: &[u8]) {
        if pkt.len() < HEADER_SIZE + 16 {
            return;
        }
        let receiver_idx = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        let counter = u64::from_be_bytes([
            pkt[8], pkt[9], pkt[10], pkt[11], pkt[12], pkt[13], pkt[14], pkt[15],
        ]);
        // Stage 1: decrypt inside the session borrow (replay window advances
        // only on successful open).
        let opened = {
            let Some(session) = self.sessions.lookup(receiver_idx) else {
                return;
            };
            let mut pt = [0u8; 4096];
            match session.open(pkt, counter, &mut pt) {
                Ok(n) => Some((
                    session.bound,
                    session.handshake_hash,
                    session.local_index,
                    pt,
                    n,
                )),
                Err(_) => None,
            }
        };
        let Some((bound, h, slot, pt, n)) = opened else {
            self.rejected_total += 1; // transport replay / decrypt failure
            self.wire.bump(WireRejectClass::Transport);
            return;
        };
        let plain = &pt[..n];
        if bound {
            self.handle_envelope(plain);
        } else {
            self.handle_binding(plain, h, slot, receiver_idx);
        }
    }

    fn handle_binding(
        &mut self,
        plain: &[u8],
        handshake_hash: [u8; 32],
        slot: u32,
        receiver_idx: u32,
    ) {
        // plaintext = u16be(cert_len) || cert || binding_sig (64B, ed25519)
        if plain.len() < 2 + 64 {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::Binding);
            return;
        }
        let cert_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
        if plain.len() < 2 + cert_len + 64 {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::Binding);
            return;
        }
        let (cert_wire, bind_sig) = (
            &plain[2..2 + cert_len],
            &plain[2 + cert_len..2 + cert_len + 64],
        );
        let Ok(cert) = codec::parse_cert(cert_wire) else {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::Binding);
            return;
        };
        let Some(peer_static) = self.peer_static[slot as usize] else {
            return;
        };
        let view = CertView {
            sig_pubkey: cert.sig_pubkey,
            kex_pubkey: cert.kex_pubkey,
            role_bits: cert.role_bits,
            not_before: cert.not_before,
            not_after: cert.not_after,
            tbs: cert.tbs,
            ca_sigs: cert.ca_sigs,
            ca_sig_count: cert.ca_sig_count as usize,
        };
        let ca_refs: Vec<&[u8]> = self.keys.ca_pubs.iter().map(|k| k.as_slice()).collect();
        let now = now_ms();
        match binding::bind_session(
            &view,
            bind_sig,
            &handshake_hash,
            &peer_static,
            &ca_refs,
            now,
        ) {
            Ok(()) => {
                if let Some(session) = self.sessions.lookup(receiver_idx) {
                    session.bound = true;
                }
                self.certs
                    .push((cert.sig_pubkey.to_vec(), cert_wire.to_vec()));
            }
            Err(_) => {
                // F1/BE-TR-01 failure: packet dropped, session stays unbound
                self.rejected_total += 1;
                self.wire.bump(WireRejectClass::Binding);
            }
        }
    }

    fn handle_envelope(&mut self, plain: &[u8]) {
        let Ok(env) = parse_envelope(plain) else {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::Parse);
            return;
        };
        if env.sender.len() != 32 || env.channel_id.len() != 32 {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::Parse);
            return;
        }
        // Sig gate FIRST (ladder C declared physics: sig before seq/parents)
        if let Err(ve) = verify_envelope(&env) {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::from(ve));
            return;
        }
        let sender: [u8; 32] = env.sender.try_into().expect("len checked");
        let channel: [u8; 32] = env.channel_id.try_into().expect("len checked");
        if env.parents.len() != env.parent_count as usize * 32 {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::Parse);
            return;
        }
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let parents: Vec<[u8; 32]> = env
            .parents
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32B chunk"))
            .collect();
        let hash = envelope_hash(plain);
        // Idempotent duplicate: same (sender, channel, seq) + same hash ->
        // ledger dedupe, NO dispatch, NO event (ladder C c2).
        if let Some(existing) = self.mem.find_envelope(&sender, &channel, env.seq) {
            if *existing == hash {
                return;
            }
            self.rejected_total += 1; // BE-ENV-05 equivocation
            self.wire.bump(WireRejectClass::VEquivocation);
            return;
        }
        // F5: parents BEFORE seq BEFORE insert (no seq consumption on failure)
        if let Err(ve) =
            verify_envelope_admission(&mut self.mem, &hash, &sender, &channel, env.seq, &parents)
        {
            self.rejected_total += 1;
            self.wire.bump(WireRejectClass::from(ve));
            return;
        }
        self.dispatch_envelope(plain, now_ms());
    }

    fn dispatch_envelope(&mut self, plain: &[u8], now: u64) {
        let sig_pub = self.keys.sig_pub();
        let parsed_own = if self.keys.cert.is_empty() {
            None
        } else {
            codec::parse_cert(&self.keys.cert).ok()
        };
        let own_cert = match parsed_own {
            Some(c) => c,
            // unbound-accept mode (no cert.bin): inert placeholder, the
            // intent/grant/refusal paths never read own_cert
            None => codec::Cert {
                version: 0,
                role_bits: 0,
                sig_pubkey: &[],
                kex_pubkey: &[],
                not_before: 0,
                not_after: 0,
                name: &[],
                scope_count: 0,
                scope_ids: &[],
                ca_sig_count: 0,
                ca_sigs: &[],
                tbs: &[],
            },
        };
        let ca_refs: Vec<&[u8]> = self.keys.ca_pubs.iter().map(|k| k.as_slice()).collect();
        {
            let resolver = &self.resolver;
            let intents = &mut self.intents;
            let senders = &mut self.senders;
            let ledger = &mut self.ledger;
            let certs = &self.certs;
            // Pre-parsed sender certs: the hook must hand back a Cert that
            // borrows storage outliving the call, so parse once up front.
            let parsed_certs: Vec<(Vec<u8>, codec::Cert)> = certs
                .iter()
                .filter_map(|(k, w)| codec::parse_cert(w).ok().map(|c| (k.clone(), c)))
                .collect();
            // Shipped effect path is fail-closed (D-089): commit consumed
            // durably, refuse to execute. Orphan tombstone lands with the
            // effect backend (Zig daemon.zig parity). RefCell keeps the hook
            // a `Fn` over the mutable ledger (single-threaded by E4).
            let ledger_cell = std::cell::RefCell::new(&mut *ledger);
            let execute_effect = |g: &codec::Grant| -> EffectOutcome {
                let mut gid = [0u8; GRANT_ID_LEN];
                if g.grant_id.len() == GRANT_ID_LEN {
                    gid.copy_from_slice(g.grant_id);
                }
                if let Ok(mut l) = ledger_cell.try_borrow_mut() {
                    if let Some(lg) = l.as_mut() {
                        let _ = lg.commit_consumed(&gid, g.not_after, now);
                    }
                }
                EffectOutcome::Refused
            };
            let cert_for_sender = |sender: &[u8]| -> Option<codec::Cert> {
                parsed_certs
                    .iter()
                    .find(|(k, _)| k.as_slice() == sender)
                    .map(|(_, c)| c.clone())
            };
            let on_rejected = |_b: &[u8]| {};
            let is_revoked = |_p: &[u8]| false;
            let already_consumed = |gid: &[u8], _e: u64, _n: u64| -> bool {
                let mut arr = [0u8; GRANT_ID_LEN];
                if gid.len() == GRANT_ID_LEN {
                    arr.copy_from_slice(gid);
                }
                ledger_cell
                    .try_borrow()
                    .map(|l| l.as_ref().map(|lg| lg.is_consumed(&arr)).unwrap_or(false))
                    .unwrap_or(false)
            };
            let hooks = Hooks {
                execute_effect: &execute_effect,
                cert_for_sender: &cert_for_sender,
                on_rejected: &on_rejected,
                is_revoked: &is_revoked,
                already_consumed: &already_consumed,
            };
            let mut d = Dispatch {
                resolver,
                intent_table: intents,
                sender_table: senders,
                own_pubkey: &sig_pub,
                own_cert,
                trusted_ca_keys: &ca_refs,
            };
            match d.dispatch(plain, &hooks, now) {
                Ok(outcome) => {
                    let tag = match outcome {
                        Outcome::IntentAdmitted => {
                            self.wire.admissions_total += 1;
                            Some(EventTag::IntentAdmitted)
                        }
                        Outcome::GrantExecuted => Some(EventTag::GrantExecuted),
                        Outcome::EffectRefused => Some(EventTag::EffectRefused),
                        Outcome::RefusalApplied => Some(EventTag::RefusalApplied),
                        Outcome::Control => Some(EventTag::ControlApplied),
                        // no ring tags exist for these two (declared delta)
                        Outcome::Effect | Outcome::Utterance => None,
                    };
                    if let Some(t) = tag {
                        self.ring.publish(t);
                    }
                }
                Err(de) => {
                    self.rejected_total += 1;
                    self.wire.bump(WireRejectClass::from(de));
                }
            }
        }
    }
}

/// Routing context: the authority state a request touches, split from self.
struct RouteCtx<'a> {
    intents: &'a mut intent::Table,
    resolver: &'a mut Resolver,
    ring: &'a mut EventRing,
    metrics: &'a mut Metrics,
    token: Option<&'a [u8; token::TOKEN_HEX_LEN]>,
    auth_refused: &'a mut u64,
    now: u64,
}

/// Route one fully-buffered HTTP request. Bearer token required on every
/// route except /healthz (F7), matching the Zig control plane.
fn route_http(conn: &mut Connection, ctx: RouteCtx<'_>) -> Result<(), String> {
    let req = match http_parse::parse(&conn.buf) {
        Ok(r) => r,
        Err(_) => return conn.write_response(400, b"bad request\n"),
    };
    let target = conn.buf[req.target_start..req.target_end].to_vec();
    let healthz = target == b"/healthz";
    if let Some(expected) = ctx.token {
        if !bearer_ok(&conn.buf, expected) {
            *ctx.auth_refused += 1;
            return conn.write_response(403, b"forbidden\n");
        }
    } else if !healthz {
        // no token minted: control plane stays fail-closed except healthz
        return conn.write_response(403, b"forbidden\n");
    }
    let body_range = req.body_start..(req.body_start + req.content_length).min(conn.buf.len());
    let reply = match (req.method, target.as_slice()) {
        (Method::Get, b"/healthz") => (200, b"ok\n".to_vec()),
        (Method::Post, b"/v1/intents") => {
            let body = String::from_utf8_lossy(&conn.buf[body_range]).into_owned();
            match control_api::post_intent(
                &body,
                ctx.resolver,
                ctx.intents,
                ctx.metrics,
                ctx.ring,
                ctx.now,
            ) {
                Ok(control_api::IntentOutcome::Accepted) => (202, b"accepted\n".to_vec()),
                Ok(control_api::IntentOutcome::AcceptedIdempotent) => {
                    (202, b"idempotent\n".to_vec())
                }
                Err(e) => (e.status(), "error\n".to_string().into_bytes()),
            }
        }
        (Method::Get, t) if t.starts_with(b"/v1/intents/") => {
            let id_hex = &t[b"/v1/intents/".len()..];
            match control_api::parse_id_hex(std::str::from_utf8(id_hex).unwrap_or("")) {
                Ok(id) => match control_api::get_intent_state(&id, ctx.intents) {
                    Ok(state) => (200, format!("{state}\n").into_bytes()),
                    Err(e) => (e.status(), b"error\n".to_vec()),
                },
                Err(e) => (e.status(), b"error\n".to_vec()),
            }
        }
        (Method::Get, t) if t.starts_with(b"/v1/events") => {
            let since = extract_since(&conn.buf, req.query_start).unwrap_or(0);
            (
                200,
                control_api::events_sse_body(ctx.ring, since).into_bytes(),
            )
        }
        (Method::Get, b"/metrics") => (
            200,
            control_api::metrics_body(ctx.metrics.admitted_total, 0, 0, 0).into_bytes(),
        ),
        (Method::Get | Method::Post, _) => (404, b"not found\n".to_vec()),
    };
    conn.write_response(reply.0, &reply.1)
}

/// Constant-time bearer check against the control token hex.
fn bearer_ok(buf: &[u8], expected: &[u8; token::TOKEN_HEX_LEN]) -> bool {
    let headers_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let headers = &buf[..headers_end];
    let lower = |b: u8| b.to_ascii_lowercase();
    let needle = b"authorization: bearer ";
    let mut i = 0;
    while i + needle.len() <= headers.len() {
        if headers[i..i + needle.len()]
            .iter()
            .map(|b| lower(*b))
            .eq(needle.iter().copied())
        {
            let rest = &headers[i + needle.len()..];
            let end = rest.iter().position(|b| *b == b'\r').unwrap_or(rest.len());
            return token::verify(&rest[..end], expected);
        }
        i += 1;
    }
    false
}

fn extract_since(buf: &[u8], query_start: Option<usize>) -> Option<u64> {
    let qs = query_start?;
    let rest = &buf[qs + 1..];
    let end = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
    control_api::parse_since(std::str::from_utf8(&rest[..end]).ok()?).ok()
}
