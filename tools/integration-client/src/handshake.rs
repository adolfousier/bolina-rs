//! Noise_IK handshake exchange (client = initiator).

use std::net::{SocketAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use bolina::transport::noise::{
    HandshakeResult, Initiator, MSG1_SIZE, MSG2_SIZE, OFF2_SENDER_INDEX,
};
use bolina::transport::session::{Session, HEADER_SIZE};

use crate::keys::ClientKeys;

pub struct Exchange {
    pub result: HandshakeResult,
    /// Client-side send state: peer_index = daemon's announced index,
    /// send.key = initiator send key, counter starts at 0.
    pub session: Session,
    pub daemon_index: u32,
}

pub fn exchange(
    socket: &UdpSocket,
    daemon: SocketAddr,
    ck: &ClientKeys,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    our_index: u32,
) -> Result<Exchange, String> {
    let mut initiator = Initiator::new(ck.kex, daemon_kex_pub);
    let mut msg1 = [0u8; MSG1_SIZE];
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    initiator
        .write_initiation(&mut msg1, our_index, ts, &daemon_sig_pub, &[0u8; 16])
        .map_err(|e| format!("write_initiation: {e:?}"))?;
    socket
        .send_to(&msg1, daemon)
        .map_err(|e| format!("msg1 send_to: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, _) = socket.recv_from(&mut buf).map_err(|e| {
        format!("msg2 wait failed: {e} - against an unwired daemon this is the expected step-1 failure (design section 9)")
    })?;
    if n != MSG2_SIZE {
        return Err(format!("msg2 size {n} != {MSG2_SIZE}"));
    }
    let mut m2 = [0u8; MSG2_SIZE];
    m2.copy_from_slice(&buf[..MSG2_SIZE]);
    initiator
        .read_response(&m2, &daemon_sig_pub)
        .map_err(|e| format!("read_response: {e:?}"))?;
    let result = initiator.finalize();

    let di = OFF2_SENDER_INDEX;
    let daemon_index = u32::from_be_bytes([m2[di], m2[di + 1], m2[di + 2], m2[di + 3]]);

    let mut session = Session::new();
    session.peer_index = daemon_index;
    session.send.key = result.send_key;
    session.bound = true; // client-side bookkeeping only

    Ok(Exchange { result, session, daemon_index })
}

/// Handshake + binding frame in one step (shared by all ladders).
/// Returns the exchange with the client session armed and the binding
/// frame already sent (counter 0).
pub fn open_bound_session(
    socket: &UdpSocket,
    daemon: SocketAddr,
    ck: &ClientKeys,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    our_index: u32,
) -> Result<(Exchange, usize), String> {
    let mut ex = exchange(socket, daemon, ck, daemon_kex_pub, daemon_sig_pub, our_index)?;

use bolina::transport::binding::DOMAIN_BINDING;
    use ed25519_dalek::Signer;
    use std::time::SystemTime;

    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let cert = crate::keys::build_cert(ck, t.saturating_sub(1_000), t + 3_600_000);
    let bind_input = [vec![DOMAIN_BINDING], ex.result.handshake_hash.to_vec()].concat();
    let bind_sig = ck.sig.sign(&bind_input);
    let mut binding_pt = cert;
    binding_pt.extend_from_slice(bind_sig.to_bytes().as_slice());

    let mut wire = vec![0u8; HEADER_SIZE + binding_pt.len() + 16];
    let n = ex
        .session
        .seal(&mut wire, &binding_pt)
        .map_err(|e| format!("binding seal: {e:?}"))?;
    wire.truncate(n);
    socket
        .send_to(&wire, daemon)
        .map_err(|e| format!("binding send_to: {e}"))?;
    Ok((ex, n))
}
