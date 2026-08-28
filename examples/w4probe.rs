//! W4 probe v1b: msg1 via write_initiation (library path, ramp keys).
use bolina::transport::noise::{Initiator, KeyPair, MSG1_SIZE};
fn fixed(n: u8) -> [u8; 32] { let mut a = [0u8; 32]; for (i, b) in a.iter_mut().enumerate() { *b = n.wrapping_add(i as u8); } a }
fn main() {
    let daemon_static = KeyPair::from_secret(fixed(0x31));
    let daemon_sig = fixed(0x77);
    let mut i = Initiator::new(KeyPair::from_secret(fixed(0x21)), daemon_static.public);
    let mut msg1 = [0u8; MSG1_SIZE];
    i.write_initiation(&mut msg1, 0xA70F1E, 1700000010000, &daemon_sig, &[0; 16]).unwrap();
    println!("msg1={}", msg1.map(|b| format!("{b:02x}")).concat());
}
