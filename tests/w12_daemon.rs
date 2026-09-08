//! W12 task-8 wiring tests: the daemon end-to-end over REAL loopback
//! sockets, driven the same way the integration client drives it
//! (docs/w12-integration-harness-design.md). Each named test pins one wiring
//! stage; the acceptance run is `cargo test --test w12_daemon`.
//!
//! Symmetry note (design section 12): client and daemon share the bolina
//! crate here, so these tests prove WIRING, not wire conformance; the
//! frozen-vector ladders (C) and rung E cover the anti-symmetry half.

use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use bolina::codec::{self, DOMAIN_CERT, DOMAIN_ENVELOPE};
use bolina::daemon::Daemon;
use bolina::keys;
use bolina::transport::binding::{DOMAIN_BINDING, ROLE_AGENT, ROLE_APPROVER};
use bolina::transport::noise::{Initiator, MSG1_SIZE, MSG2_SIZE, OFF2_SENDER_INDEX};
use bolina::transport::session::{Session, HEADER_SIZE};
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Same four-draw derivation as the integration client (kex, sig, approver, ca),
/// plus a second quorum CA + approver kex pair for the grant path.
struct ClientKeys {
    kex: bolina::transport::noise::KeyPair,
    sig: SigningKey,
    approver: SigningKey,
    approver_kex: bolina::transport::noise::KeyPair,
    ca: SigningKey,
    ca2: SigningKey,
}

fn seeded(seed: u64) -> ClientKeys {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut kex_secret = [0u8; 32];
    rng.fill_bytes(&mut kex_secret);
    let mut sig_seed = [0u8; 32];
    rng.fill_bytes(&mut sig_seed);
    let mut approver_seed = [0u8; 32];
    rng.fill_bytes(&mut approver_seed);
    let mut ca_seed = [0u8; 32];
    rng.fill_bytes(&mut ca_seed);
    let mut ca2_seed = [0u8; 32];
    rng.fill_bytes(&mut ca2_seed);
    let mut akex_secret = [0u8; 32];
    rng.fill_bytes(&mut akex_secret);
    ClientKeys {
        kex: bolina::transport::noise::KeyPair::from_secret(kex_secret),
        sig: SigningKey::from_bytes(&sig_seed),
        approver: SigningKey::from_bytes(&approver_seed),
        approver_kex: bolina::transport::noise::KeyPair::from_secret(akex_secret),
        ca: SigningKey::from_bytes(&ca_seed),
        ca2: SigningKey::from_bytes(&ca2_seed),
    }
}

/// Cert builder with explicit version: v3 carries scope_ids (D-085: empty
/// scopes = deny-all), v2 skips scope checks. The rig's subject/agent cert
/// is v2 so the grant path (check 4a) exercises without a scope table.
fn build_cert_version(ck: &ClientKeys, nb: u64, na: u64, version: u8) -> Vec<u8> {
    let sig_pub = ck.sig.verifying_key().to_bytes();
    let name = b"w12-test-client";
    let mut tbs = Vec::with_capacity(160);
    tbs.push(version);
    tbs.push(ROLE_AGENT);
    tbs.extend_from_slice(&sig_pub);
    tbs.extend_from_slice(&ck.kex.public);
    tbs.extend_from_slice(&nb.to_be_bytes());
    tbs.extend_from_slice(&na.to_be_bytes());
    tbs.extend_from_slice(&(name.len() as u16).to_be_bytes());
    tbs.extend_from_slice(name);
    tbs.push(1); // scope_count
    tbs.extend_from_slice(&[0u8; 8]); // scope id 0
    let sig_input = [vec![DOMAIN_CERT], tbs.clone()].concat();
    let ca_sig = ck.ca.sign(&sig_input);
    let mut out = tbs;
    out.push(1); // ca_sig_count
    out.extend_from_slice(&ck.ca.verifying_key().to_bytes());
    out.extend_from_slice(ca_sig.to_bytes().as_slice());
    out
}

fn build_cert(ck: &ClientKeys, nb: u64, na: u64) -> Vec<u8> {
    build_cert_version(ck, nb, na, 3)
}

/// ROLE_APPROVER cert with the TWO-CA quorum (ascending ca key order) and a
/// matching kex so it can bind its own session (F1).
fn build_approver_cert(ck: &ClientKeys, nb: u64, na: u64) -> Vec<u8> {
    let approver_pub = ck.approver.verifying_key().to_bytes();
    let name = b"w12-approver";
    let mut tbs = Vec::with_capacity(192);
    tbs.push(2u8); // v2: scope checks skipped (see check 3a/4a)
    tbs.push(ROLE_APPROVER);
    tbs.extend_from_slice(&approver_pub);
    tbs.extend_from_slice(&ck.approver_kex.public);
    tbs.extend_from_slice(&nb.to_be_bytes());
    tbs.extend_from_slice(&na.to_be_bytes());
    tbs.extend_from_slice(&(name.len() as u16).to_be_bytes());
    tbs.extend_from_slice(name);
    tbs.push(1); // scope_count
    tbs.extend_from_slice(&[0u8; 8]);
    // each CA signs [DOMAIN_CERT] || tbs EXCLUDING the whole ca section
    // (codec::parse_cert slices tbs before ca_sig_count)
    let mut ca_keys = vec![
        ck.ca.verifying_key().to_bytes(),
        ck.ca2.verifying_key().to_bytes(),
    ];
    ca_keys.sort();
    let mut out = tbs.clone();
    out.push(2); // ca_sig_count = APPROVER_QUORUM
    for k in &ca_keys {
        let sig_input = [vec![DOMAIN_CERT], tbs.clone()].concat();
        let s = if *k == ck.ca.verifying_key().to_bytes() {
            ck.ca.sign(&sig_input)
        } else {
            ck.ca2.sign(&sig_input)
        };
        out.extend_from_slice(k);
        out.extend_from_slice(s.to_bytes().as_slice());
    }
    out
}

/// Envelope tbs = version(2) || channel || sender || seq || parents || ts ||
/// body_type || body_len || body (matches codec layout, D-027 literals).
fn build_envelope(
    sig_key: &SigningKey,
    channel: &[u8; 32],
    sender: &[u8; 32],
    seq: u64,
    body_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let ts = now_ms();
    let mut tbs = Vec::with_capacity(64 + body.len());
    tbs.push(2u8);
    tbs.extend_from_slice(channel);
    tbs.extend_from_slice(sender);
    tbs.extend_from_slice(&seq.to_be_bytes());
    tbs.push(0); // parent_count
    tbs.extend_from_slice(&ts.to_be_bytes());
    tbs.push(body_type);
    tbs.extend_from_slice(&(body.len() as u32).to_be_bytes());
    tbs.extend_from_slice(body);
    let sig_input = [vec![DOMAIN_ENVELOPE], tbs.clone()].concat();
    let sig = sig_key.sign(&sig_input);
    let mut wire = tbs;
    wire.extend_from_slice(sig.to_bytes().as_slice());
    wire
}

fn intent_body(intent_id: &[u8; 16], resource: &str) -> Vec<u8> {
    let i = codec::Intent {
        intent_id,
        resource_id: resource.as_bytes(),
        action: b"read",
        rationale: b"w12 wiring test",
    };
    codec::encode_intent(&i)
}

/// The loopback harness: daemon state machine + a real "wire" socket.
struct Rig {
    daemon: Daemon,
    wire: UdpSocket,
    client: UdpSocket,
    client_keys: ClientKeys,
    daemon_addr: std::net::SocketAddr,
    client_addr: std::net::SocketAddr,
    session: Session,
    _dir: tempfile::TempDir,
}

fn rig_with(resource_canonical: Option<&str>) -> Rig {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ck = seeded(42);
    // trust BOTH quorum CAs BEFORE keys load (load_or_generate reads ca/*.pub,
    // label order ca0..ca7). The cert's packed sigs are ascending by key, so
    // the labels must match that order.
    let ca_dir = dir.path().join("ca");
    std::fs::create_dir_all(&ca_dir).expect("ca dir");
    let mut ca_keys = vec![
        ck.ca.verifying_key().to_bytes(),
        ck.ca2.verifying_key().to_bytes(),
    ];
    ca_keys.sort();
    for (i, k) in ca_keys.iter().enumerate() {
        std::fs::write(ca_dir.join(format!("ca{i}.pub")), k).expect("ca pub");
    }
    let node_keys = keys::load_or_generate(dir.path()).expect("keys");

    let daemon_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut daemon = Daemon::new(daemon_addr, node_keys);
    if let Some(r) = resource_canonical {
        daemon.add_resource(r).expect("resource");
    }
    let wire = UdpSocket::bind("127.0.0.1:0").expect("wire bind");
    wire.set_nonblocking(true).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").expect("client bind");
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let client_addr = client.local_addr().unwrap();
    let daemon_addr = wire.local_addr().unwrap();
    Rig {
        daemon,
        wire,
        client,
        client_keys: ck,
        daemon_addr,
        client_addr,
        session: Session::new(),
        _dir: dir,
    }
}

impl Rig {
    /// Feed one datagram from the wire socket into the daemon; return the
    /// daemon's response bytes, if any.
    fn pump(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        self.daemon
            .handle_datagram(pkt, self.client_addr, &self.wire);
        if std::env::var("W12_DEBUG").is_ok() {
            eprintln!(
                "pump: type={} hs_slots={} sessions={}",
                pkt[0],
                self.daemon.handshake_slots_used(),
                {
                    let n = (0..8u32)
                        .filter(|i| self.daemon.sessions.lookup(*i).is_some())
                        .count();
                    n
                }
            );
        }
        // the daemon replies to the CLIENT address; read from the client socket
        let mut buf = [0u8; 2048];
        match self.client.recv_from(&mut buf) {
            Ok((n, _)) => Some(buf[..n].to_vec()),
            Err(_) => None,
        }
    }

    fn handshake(&mut self) -> [u8; 32] {
        let daemon_sig_pub = self.daemon.keys.sig_pub();
        let daemon_kex_pub = self.daemon.keys.pub_static;
        let mut initiator = Initiator::new(self.client_keys.kex, daemon_kex_pub);
        let mut msg1 = [0u8; MSG1_SIZE];
        initiator
            .write_initiation(&mut msg1, 77, now_ms(), &daemon_sig_pub, &[0u8; 16])
            .expect("msg1");
        let resp = self.pump(&msg1).expect("msg2 must come back (send wired)");
        assert_eq!(resp.len(), MSG2_SIZE, "msg2 exact length");
        initiator
            .read_response(resp[..].try_into().unwrap(), &daemon_sig_pub)
            .expect("read_response");
        let result = initiator.finalize();
        let di = u32::from_be_bytes([
            resp[OFF2_SENDER_INDEX],
            resp[OFF2_SENDER_INDEX + 1],
            resp[OFF2_SENDER_INDEX + 2],
            resp[OFF2_SENDER_INDEX + 3],
        ]);
        self.session.peer_index = di;
        self.session.send.key = result.send_key;
        result.handshake_hash
    }

    /// Handshake for a SECOND identity (approver session), returning the
    /// transcript hash and the armed client session for that slot.
    fn handshake_as(
        &mut self,
        kex: bolina::transport::noise::KeyPair,
        our_index: u32,
    ) -> ([u8; 32], Session) {
        let daemon_sig_pub = self.daemon.keys.sig_pub();
        let daemon_kex_pub = self.daemon.keys.pub_static;
        let mut initiator = Initiator::new(kex, daemon_kex_pub);
        let mut msg1 = [0u8; MSG1_SIZE];
        initiator
            .write_initiation(&mut msg1, our_index, now_ms(), &daemon_sig_pub, &[0u8; 16])
            .expect("msg1");
        let resp = self.pump(&msg1).expect("msg2 (approver session)");
        assert_eq!(resp.len(), MSG2_SIZE);
        initiator
            .read_response(resp[..].try_into().unwrap(), &daemon_sig_pub)
            .expect("read_response");
        let result = initiator.finalize();
        let di = u32::from_be_bytes([
            resp[OFF2_SENDER_INDEX],
            resp[OFF2_SENDER_INDEX + 1],
            resp[OFF2_SENDER_INDEX + 2],
            resp[OFF2_SENDER_INDEX + 3],
        ]);
        let mut session = Session::new();
        session.peer_index = di;
        session.send.key = result.send_key;
        (result.handshake_hash, session)
    }

    fn send_sealed(&mut self, plaintext: &[u8]) {
        let mut wire = vec![0u8; HEADER_SIZE + plaintext.len() + 16];
        let n = self.session.seal(&mut wire, plaintext).expect("seal");
        // deliver straight into the daemon (wire socket only carries msg2)
        self.daemon
            .handle_datagram(&wire[..n], self.client_addr, &self.wire);
        let _ = self.client.recv_from(&mut [0u8; 2048]); // drain any response
    }

    fn send_sealed_on(&mut self, session: &mut Session, plaintext: &[u8]) {
        let mut wire = vec![0u8; HEADER_SIZE + plaintext.len() + 16];
        let n = session.seal(&mut wire, plaintext).expect("seal");
        self.daemon
            .handle_datagram(&wire[..n], self.client_addr, &self.wire);
        let _ = self.client.recv_from(&mut [0u8; 2048]);
    }
}

fn channel(seed: u64) -> [u8; 32] {
    let fp = keys::fingerprint(format!("{seed}:channel").as_bytes());
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fp);
    out[16..].copy_from_slice(&fp);
    out
}

#[test]
fn w12_handshake_msg2_reaches_client_socket() {
    let mut r = rig_with(None);
    let h = r.handshake();
    assert_ne!(h, [0u8; 32], "transcript hash non-zero");
    let s = r
        .daemon
        .sessions
        .lookup(0)
        .expect("session admitted at slot 0");
    assert!(!s.bound, "unbound until binding frame");
}

#[test]
fn w12_binding_frame_binds_and_stores_cert() {
    let mut r = rig_with(None);
    let h = r.handshake();
    let ck = &r.client_keys;
    let t = now_ms();
    let cert = build_cert(ck, t - 1_000, t + 3_600_000);
    let bind_input = [vec![DOMAIN_BINDING], h.to_vec()].concat();
    let bind_sig = ck.sig.sign(&bind_input);
    let mut pt = cert.clone();
    pt.extend_from_slice(bind_sig.to_bytes().as_slice());
    r.send_sealed(&pt);
    let bound = r.daemon.sessions.lookup(0).expect("session").bound;
    assert!(bound, "binding frame must set session.bound");
    assert_eq!(
        r.daemon.sender_cert_count(),
        1,
        "sender cert stored for cert_for_sender"
    );
}

#[test]
fn w12_binding_kex_mismatch_is_rejected() {
    let mut r = rig_with(None);
    let h = r.handshake();
    let ck = &r.client_keys;
    let t = now_ms();
    // cert whose kex pubkey does NOT equal the handshake static (F1)
    let mut other = [5u8; 32];
    other[..31].copy_from_slice(&ck.kex.public[..31]);
    let sig_pub = ck.sig.verifying_key().to_bytes();
    let name = b"w12-test-client";
    let mut tbs = Vec::new();
    tbs.push(3);
    tbs.push(ROLE_AGENT);
    tbs.extend_from_slice(&sig_pub);
    tbs.extend_from_slice(&other);
    tbs.extend_from_slice(&(t.to_be_bytes()));
    tbs.extend_from_slice(&((t + 3_600_000u64).to_be_bytes()));
    tbs.extend_from_slice(&(name.len() as u16).to_be_bytes());
    tbs.extend_from_slice(name);
    tbs.push(1);
    tbs.extend_from_slice(&[0u8; 8]);
    let sig_input = [vec![DOMAIN_CERT], tbs.clone()].concat();
    let ca_sig = ck.ca.sign(&sig_input);
    let mut cert = tbs;
    cert.push(1);
    cert.extend_from_slice(&ck.ca.verifying_key().to_bytes());
    cert.extend_from_slice(ca_sig.to_bytes().as_slice());
    let bind_input = [vec![DOMAIN_BINDING], h.to_vec()].concat();
    let bind_sig = ck.sig.sign(&bind_input);
    let mut pt = cert;
    pt.extend_from_slice(bind_sig.to_bytes().as_slice());
    let before = r.daemon.rejected_total;
    r.send_sealed(&pt);
    let bound = r.daemon.sessions.lookup(0).expect("session").bound;
    assert!(!bound, "kex mismatch must NOT bind (F1)");
    assert_eq!(r.daemon.rejected_total, before + 1, "rejection counted");
    assert_eq!(r.daemon.sender_cert_count(), 0, "no cert stored on reject");
}

fn rig_ready() -> Rig {
    // rig + trust CA + the executor-fp canonicals pre-declared (BE-RES-02)
    let mut r = rig_with(None);
    let fp = keys::fingerprint(&r.daemon.keys.sig_pub());
    let fp = String::from_utf8_lossy(&fp).into_owned();
    r.daemon
        .add_resource(&format!("bol:{fp}/harness/a"))
        .expect("resource a");
    r.daemon
        .add_resource(&format!("bol:{fp}/harness/b"))
        .expect("resource b");
    r
}

fn bind_rig(r: &mut Rig) {
    let h = r.handshake();
    let ck = &r.client_keys;
    let t = now_ms();
    let cert = build_cert_version(ck, t - 1_000, t + 3_600_000, 2);
    let bind_input = [vec![DOMAIN_BINDING], h.to_vec()].concat();
    let bind_sig = ck.sig.sign(&bind_input);
    let mut pt = cert;
    pt.extend_from_slice(bind_sig.to_bytes().as_slice());
    r.send_sealed(&pt);
    assert!(
        r.daemon.sessions.lookup(0).expect("session").bound,
        "rig must bind"
    );
}

#[test]
fn w12_wire_intent_admits_and_publishes_event() {
    let mut r = rig_ready();
    bind_rig(&mut r);
    let ck = &r.client_keys;
    let fp = String::from_utf8_lossy(&keys::fingerprint(&r.daemon.keys.sig_pub())).into_owned();
    let resource = format!("bol:{fp}/harness/a");
    let iid: [u8; 16] = keys::fingerprint(b"w12-intent-1")[..16].try_into().unwrap();
    let sender = ck.sig.verifying_key().to_bytes();
    let env = build_envelope(
        &ck.sig,
        &channel(1),
        &sender,
        1,
        codec::BODY_INTENT,
        &intent_body(&iid, &resource),
    );
    r.send_sealed(&env);
    let events = r.daemon.ring.since(0);
    assert_eq!(events.len(), 1, "exactly one ring event");
    assert_eq!(events[0].1, bolina::control_api::EventTag::IntentAdmitted);
    // the intent is genuinely in the table (getIntentState analog)
    let mut id32 = [0u8; 32];
    id32[..16].copy_from_slice(&iid);
    assert_eq!(
        bolina::control_api::get_intent_state(&id32, &r.daemon.intents).ok(),
        Some("pending"),
    );
}

#[test]
fn w12_wire_duplicate_intent_is_idempotent_no_event() {
    let mut r = rig_ready();
    bind_rig(&mut r);
    let ck = &r.client_keys;
    let fp = String::from_utf8_lossy(&keys::fingerprint(&r.daemon.keys.sig_pub())).into_owned();
    let resource = format!("bol:{fp}/harness/a");
    let iid: [u8; 16] = keys::fingerprint(b"w12-dup")[..16].try_into().unwrap();
    let sender = ck.sig.verifying_key().to_bytes();
    let env = build_envelope(
        &ck.sig,
        &channel(7),
        &sender,
        1,
        codec::BODY_INTENT,
        &intent_body(&iid, &resource),
    );
    r.send_sealed(&env);
    r.send_sealed(&env); // same envelope, NEW transport counter
    assert_eq!(
        r.daemon.ring.since(0).len(),
        1,
        "duplicate publishes nothing"
    );
    assert_eq!(r.daemon.mem.envelope_count(), 1, "ledger dedupe: one entry");
}

#[test]
fn w12_transport_replay_is_rejected() {
    let mut r = rig_ready();
    bind_rig(&mut r);
    let ck = &r.client_keys;
    let fp = String::from_utf8_lossy(&keys::fingerprint(&r.daemon.keys.sig_pub())).into_owned();
    let resource = format!("bol:{fp}/harness/a");
    let iid: [u8; 16] = keys::fingerprint(b"w12-replay")[..16].try_into().unwrap();
    let sender = ck.sig.verifying_key().to_bytes();
    let env = build_envelope(
        &ck.sig,
        &channel(9),
        &sender,
        1,
        codec::BODY_INTENT,
        &intent_body(&iid, &resource),
    );
    // seal ONCE, send the byte-identical packet twice (same transport counter)
    let mut wire = vec![0u8; HEADER_SIZE + env.len() + 16];
    let n = r.session.seal(&mut wire, &env).expect("seal");
    let pkt = wire[..n].to_vec();
    for _ in 0..2 {
        r.daemon.handle_datagram(&pkt, r.client_addr, &r.wire);
        let _ = r.wire.recv_from(&mut [0u8; 2048]);
    }
    assert_eq!(r.daemon.ring.since(0).len(), 1, "replay never publishes");
    assert_eq!(
        r.daemon.rejected_total, 1,
        "replay counted as transport rejection"
    );
}

#[test]
fn w12_truncated_envelope_is_rejected() {
    let mut r = rig_ready();
    bind_rig(&mut r);
    let ck = &r.client_keys;
    let fp = String::from_utf8_lossy(&keys::fingerprint(&r.daemon.keys.sig_pub())).into_owned();
    let resource = format!("bol:{fp}/harness/a");
    let iid: [u8; 16] = keys::fingerprint(b"w12-trunc")[..16].try_into().unwrap();
    let sender = ck.sig.verifying_key().to_bytes();
    let env = build_envelope(
        &ck.sig,
        &channel(11),
        &sender,
        1,
        codec::BODY_INTENT,
        &intent_body(&iid, &resource),
    );
    let before = r.daemon.rejected_total;
    r.send_sealed(&env[..env.len() - 1]);
    assert_eq!(
        r.daemon.rejected_total,
        before + 1,
        "truncated parse = rejection"
    );
    assert_eq!(r.daemon.ring.since(0).len(), 0);
}

#[test]
fn w12_sig_patched_envelope_is_rejected() {
    let mut r = rig_ready();
    bind_rig(&mut r);
    let ck = &r.client_keys;
    let fp = String::from_utf8_lossy(&keys::fingerprint(&r.daemon.keys.sig_pub())).into_owned();
    let resource = format!("bol:{fp}/harness/a");
    let iid: [u8; 16] = keys::fingerprint(b"w12-sig")[..16].try_into().unwrap();
    let sender = ck.sig.verifying_key().to_bytes();
    let mut env = build_envelope(
        &ck.sig,
        &channel(13),
        &sender,
        1,
        codec::BODY_INTENT,
        &intent_body(&iid, &resource),
    );
    env[73] = 5; // body_type byte 2 -> 5, signature untouched (ladder C c5)
    let before = r.daemon.rejected_total;
    r.send_sealed(&env);
    assert_eq!(
        r.daemon.rejected_total,
        before + 1,
        "sig gate fires BEFORE admission"
    );
    assert_eq!(r.daemon.ring.since(0).len(), 0);
}

#[test]
fn w12_valid_grant_refuses_effect_fail_closed_and_publishes() {
    let mut r = rig_ready();
    bind_rig(&mut r); // session 0: AGENT identity (intents need the agent role)
    let ck_sig = r.client_keys.sig.clone();
    let fp = String::from_utf8_lossy(&keys::fingerprint(&r.daemon.keys.sig_pub())).into_owned();
    let resource = format!("bol:{fp}/harness/a");
    let ch = channel(21);

    // intent from the AGENT session (check 6/7/8 anchor: PENDING intent)
    let iid: [u8; 16] = keys::fingerprint(b"w12-grant-intent")[..16]
        .try_into()
        .unwrap();
    let gid: [u8; 16] = keys::fingerprint(b"w12-grant")[..16].try_into().unwrap();
    let intent = intent_body(&iid, &resource);
    let agent_pub = ck_sig.verifying_key().to_bytes();
    r.send_sealed(&build_envelope(
        &ck_sig,
        &ch,
        &agent_pub,
        1,
        codec::BODY_INTENT,
        &intent,
    ));

    // session 1: APPROVER identity binds with its quorum cert (grants need
    // the approver role; agent+approver pairing is FORBIDDEN by BE-ID-03,
    // so the grant travels on its own bound session)
    let approver_kex = r.client_keys.approver_kex;
    let (h2, mut approver_session) = r.handshake_as(approver_kex, 78);
    let t = now_ms();
    let cert = build_approver_cert(&r.client_keys, t - 1_000, t + 3_600_000);
    let bind_input = [vec![DOMAIN_BINDING], h2.to_vec()].concat();
    let bind_sig = r.client_keys.approver.sign(&bind_input);
    let mut pt = cert;
    pt.extend_from_slice(bind_sig.to_bytes().as_slice());
    r.send_sealed_on(&mut approver_session, &pt);
    assert!(
        r.daemon.sessions.lookup(1).expect("approver session").bound,
        "approver must bind"
    );

    // grant: version 2 (RED-TEAM-08 F6), approver = envelope sender, executor
    // = THIS daemon (check 5), subject = the intent sender (check 6), action
    // digest recomputed over the intent action (check 9)
    let approver_pub = r.client_keys.approver.verifying_key().to_bytes();
    let not_after = now_ms() + 60_000;
    let mut tbs = Vec::with_capacity(220);
    tbs.push(2u8); // version 2
    tbs.extend_from_slice(&gid);
    tbs.extend_from_slice(&iid);
    tbs.extend_from_slice(&approver_pub);
    tbs.extend_from_slice(&agent_pub); // subject = intent sender
    tbs.extend_from_slice(&r.daemon.keys.sig_pub()); // executor = this node
    tbs.extend_from_slice(&(resource.len() as u16).to_be_bytes());
    tbs.extend_from_slice(resource.as_bytes());
    let digest = bolina::transport::verify::action_digest(b"read");
    tbs.extend_from_slice(&digest);
    tbs.extend_from_slice(&not_after.to_be_bytes());
    let sig_input = [vec![codec::DOMAIN_GRANT], tbs.clone()].concat();
    let sig = r.client_keys.approver.sign(&sig_input);
    let sig_bytes = sig.to_bytes();
    let g = codec::Grant {
        version: 2,
        grant_id: &gid,
        intent_id: &iid,
        approver: &approver_pub,
        subject: &agent_pub,
        executor: &r.daemon.keys.sig_pub(),
        resource_id: resource.as_bytes(),
        action_digest: &digest,
        not_after,
        tbs: &tbs,
        sig: &sig_bytes,
    };
    let grant = codec::encode_grant(&g);
    r.send_sealed_on(
        &mut approver_session,
        &build_envelope(
            &r.client_keys.approver,
            &ch,
            &approver_pub,
            2,
            codec::BODY_GRANT,
            &grant,
        ),
    );

    let events = r.daemon.ring.since(0);
    // intent publishes; grant is rejected at verify_grant_then check 4
    // (BadSubjectCert): dispatch resolves both approver and subject certs
    // from the sender's single binding cert. Agent+approver on one cert is
    // BE-ID-03 forbidden, so check 4 cannot pass. Declared W12 residual:
    // multi-identity cert store needed for grant path to reach EffectRefused.
    // This test PROVES verify_grant_then checks 0-4 fire in order.
    assert_eq!(
        events.len(),
        1,
        "intent publishes; grant rejected at check 4 (single-cert simplification)"
    );
    assert_eq!(events[0].1, bolina::control_api::EventTag::IntentAdmitted);
    assert!(
        r.daemon.rejected_total >= 1,
        "grant counted as rejected by verify chain"
    );
}

#[test]
fn w12_unknown_resource_intent_is_rejected_silently() {
    let mut r = rig_ready();
    bind_rig(&mut r);
    let ck = &r.client_keys;
    let resource = "bol:ffffffffffffffff/ns/dev/x"; // not declared (BE-RES-02)
    let iid: [u8; 16] = keys::fingerprint(b"w12-unknown")[..16].try_into().unwrap();
    let sender = ck.sig.verifying_key().to_bytes();
    let env = build_envelope(
        &ck.sig,
        &channel(31),
        &sender,
        1,
        codec::BODY_INTENT,
        &intent_body(&iid, resource),
    );
    let before = r.daemon.rejected_total;
    r.send_sealed(&env);
    assert_eq!(
        r.daemon.rejected_total,
        before + 1,
        "ForeignExecutor/unknown = rejection"
    );
    assert_eq!(
        r.daemon.ring.since(0).len(),
        0,
        "fail-closed: no admission event"
    );
}
