//! W4 live interop against the real Zig daemon (G2 ladder, D-096):
//!   A handshake (Noise_IK msg1->msg2, transcript h)
//!   B mutual binding (daemon pushes its frame; we answer, BE-TR-01)
//!   C sealed Intent envelope -> control plane reports `pending`
//! Env: ITO_DAEMON, ITO_DAEMON_MAT, ITO_RUNNER_MAT, ITO_RESOURCE,
//!      ITO_TOKEN_FILE, ITO_CONTROL
use bolina::codec::{self, LEN_CHANNEL_ID, LEN_SIG};
use bolina::transport::noise::{
    Initiator, HandshakeResult, KeyPair, MSG1_SIZE, MSG2_SIZE,
    OFF2_RECEIVER_INDEX, OFF2_SENDER_INDEX, transport_nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

fn env(k: &str) -> String { std::env::var(k).unwrap_or_else(|_| panic!("env {k} unset")) }
fn read32(p: &str) -> [u8; 32] {
    let b = std::fs::read(p).expect(p);
    b.try_into().expect("32-byte file")
}
fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }

fn seal_t4(out_key: &[u8; 32], counter: u64, pt: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(16 + pt.len() + 16);
    pkt.push(4);
    pkt.extend_from_slice(&[0, 0, 0]); // reserved
    pkt.extend_from_slice(&0u32.to_be_bytes()); // receiver filled by caller
    pkt.extend_from_slice(&counter.to_be_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(out_key));
    // Zig Session.seal parity: the 16-byte header is the AEAD AAD.
    let aad = pkt.clone();
    let ct = cipher.encrypt(Nonce::from_slice(&transport_nonce(counter)), chacha20poly1305::aead::Payload { msg: pt, aad: &aad }).expect("seal");
    pkt.extend_from_slice(&ct);
    pkt
}
fn open_t4(in_key: &[u8; 32], counter: u64, pkt: &[u8]) -> Vec<u8> {
    assert_eq!(pkt[0], 4, "not a type-4 packet");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(in_key));
    cipher.decrypt(Nonce::from_slice(&transport_nonce(counter)), chacha20poly1305::aead::Payload { msg: &pkt[16..], aad: &pkt[..16] }).expect("open")
}

fn main() {
    let daemon_addr = env("ITO_DAEMON");
    let daemon_mat = env("ITO_DAEMON_MAT");
    let runner_mat = env("ITO_RUNNER_MAT");
    let resource = env("ITO_RESOURCE");
    let token = std::fs::read_to_string(env("ITO_TOKEN_FILE")).expect("token file").trim().to_string();

    // Identity material (CI runner 4286cba0: Noise static + Ed25519 sig + cert)
    let our_static = KeyPair::from_secret(read32(&format!("{runner_mat}/static.key")));
    let sig_seed = read32(&format!("{runner_mat}/sig.key"));
    let signing = SigningKey::from_bytes(&sig_seed);
    let our_sig_pub = signing.verifying_key().to_bytes();
    let daemon_static_pub = read32(&format!("{daemon_mat}/static.pub"));
    let daemon_sig_pub = read32(&format!("{daemon_mat}/sig.pub"));
    let our_cert = std::fs::read(format!("{runner_mat}/cert.bin")).expect("runner cert");
    let our_cert_rec = codec::parse_cert(&our_cert).expect("our cert parses");
    assert_eq!(our_cert_rec.sig_pubkey, &our_sig_pub, "cert/signing key mismatch");

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.connect(&daemon_addr).expect("connect");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
    let our_index: u32 = 0x00A7_0F1E;

    // ---- STAGE A: Noise_IK handshake -------------------------------------
    let mut initiator = Initiator::new(our_static, daemon_static_pub);
    let mut msg1 = [0u8; MSG1_SIZE];
    initiator.write_initiation(&mut msg1, our_index, now_ms(), &daemon_sig_pub, &[0; 16]).expect("msg1");
    if std::env::var("ITO_DEBUG").is_ok() { eprintln!("MSG1={}", msg1.map(|b| format!("{b:02x}")).concat()); }
    sock.send(&msg1).expect("send msg1");

    let mut msg2 = [0u8; MSG2_SIZE];
    let (n, _) = sock.recv_from(&mut msg2).expect("recv msg2");
    assert_eq!(n, MSG2_SIZE, "msg2 size");
    // G2 pin: receiver_index echoes OUR announced index; sender = daemon slot
    assert_eq!(&msg2[OFF2_RECEIVER_INDEX..OFF2_RECEIVER_INDEX + 4], &our_index.to_be_bytes(), "G2 echo index");
    let daemon_slot = u32::from_be_bytes(msg2[OFF2_SENDER_INDEX..OFF2_SENDER_INDEX + 4].try_into().unwrap());
    initiator.read_response(&msg2, &daemon_sig_pub).expect("msg2 verify");
    let hs: HandshakeResult = initiator.finalize();
    println!("STAGE A OK (handshake, daemon slot {daemon_slot:#x})");

    // ---- STAGE B: mutual binding (BE-TR-01) ------------------------------
    // Daemon pushes its binding first, sealed under its send key (= our recv).
    let mut buf = [0u8; 2048];
    let (nb, _) = sock.recv_from(&mut buf).expect("recv daemon binding");
    let daemon_pt = open_t4(&hs.recv_key, 0, &buf[..nb]);
    let cert_len = u16::from_be_bytes([daemon_pt[0], daemon_pt[1]]) as usize;
    let dcert = codec::parse_cert(&daemon_pt[2..2 + cert_len]).expect("daemon cert parses");
    assert_eq!(daemon_pt[2 + cert_len..].len(), 64, "binding sig len");
    assert_eq!(dcert.sig_pubkey, &daemon_sig_pub, "daemon cert is the daemon");
    let mut bmsg = vec![0x05u8]; // DOMAIN_BINDING
    bmsg.extend_from_slice(&hs.handshake_hash);
    VerifyingKey::from_bytes(&daemon_sig_pub).unwrap()
        .verify(&bmsg, &daemon_pt[2 + cert_len..].try_into().unwrap()).expect("daemon binding sig");
    println!("STAGE B1 OK (daemon binding verified clock-free over 0x05||h)");

    // Our binding answer: u16be cert_len | cert | sig over (0x05 || h)
    let mut frame = Vec::with_capacity(2 + our_cert.len() + 64);
    frame.extend_from_slice(&(our_cert.len() as u16).to_be_bytes());
    frame.extend_from_slice(&our_cert);
    let mut bmsg2 = vec![0x05u8];
    bmsg2.extend_from_slice(&hs.handshake_hash);
    let sig = signing.sign(&bmsg2).to_bytes();
    frame.extend_from_slice(&sig);
    let mut pkt = seal_t4(&hs.send_key, 0, &frame);
    pkt[4..8].copy_from_slice(&daemon_slot.to_be_bytes());
    sock.send(&pkt).expect("send our binding");

    // ---- STAGE C: sealed Intent envelope -> pending ----------------------
    let intent_id: [u8; 16] = [0xAB; 16];
    let intent = codec::Intent {
        intent_id: &intent_id,
        resource_id: resource.as_bytes(),
        action: b"apt-get install -y sqlite3",
        rationale: b"W4 live interop: Rust initiator against Zig daemon",
    };
    let body = codec::encode_intent(&intent);
    let mut tbs = Vec::with_capacity(150);
    tbs.push(2u8); // version (vector-pinned)
    let channel_id = [0x42u8; LEN_CHANNEL_ID];
    tbs.extend_from_slice(&channel_id);
    tbs.extend_from_slice(&our_sig_pub);
    tbs.extend_from_slice(&1u64.to_be_bytes()); // seq
    tbs.push(0); // parent_count
    tbs.extend_from_slice(&now_ms().to_be_bytes()); // ts
    tbs.push(0x02u8); // body_type = Intent (vector-pinned)
    tbs.extend_from_slice(&(body.len() as u32).to_be_bytes());
    tbs.extend_from_slice(&body);
    // BE-SIG-01: the domain tag is part of the SIGNED message only
    // (sig_input = tag || tbs); the wire carries tbs || sig, no tag byte.
    let mut signed = vec![0x02u8];
    signed.extend_from_slice(&tbs);
    let esig = signing.sign(&signed).to_bytes();
    assert_eq!(esig.len(), LEN_SIG);
    let mut env_wire = tbs.clone();
    env_wire.extend_from_slice(&esig);
    codec::parse_envelope(&env_wire).expect("our envelope round-parses");

    let mut pkt2 = seal_t4(&hs.send_key, 1, &env_wire);
    pkt2[4..8].copy_from_slice(&daemon_slot.to_be_bytes());
    sock.send(&pkt2).expect("send intent");
    std::thread::sleep(std::time::Duration::from_millis(400));

    // Control-plane verdict: the daemon must report the intent as pending.
    let want = format!("/v1/intents/{}", intent_id.map(|b| format!("{b:02x}")).concat());
    let mut req = format!("GET {want} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").into_bytes();
    use std::io::{Read, Write};
    let mut tcp = std::net::TcpStream::connect("127.0.0.1:7421").expect("control connect");
    tcp.write_all(&mut req).expect("control write");
    let mut resp = String::new();
    tcp.read_to_string(&mut resp).expect("control read");
    assert!(resp.contains(" 200 "), "control status: {}", &resp[..resp.len().min(60)]);
    assert!(resp.contains("pending"), "intent state not pending: {}", &resp[resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0)..].chars().take(160).collect::<String>());
    println!("STAGE C OK (intent admitted over live wire, control plane: pending)");
    println!("W4 INTEROP COMPLETE: Rust initiator <-> Zig daemon, G2 ladder green");
}
