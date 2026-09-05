//! W4 transport: the Noise_IK handshake machine and its DoS gate.
pub mod mac1;
pub mod noise;
pub mod session;
pub mod relay;
pub mod reassembly;
pub mod sync;
pub mod verify;
pub mod resolver;
pub mod dispatch;
pub use mac1::{compute_mac1, verify_mac1, MAC_BYTES};
pub use noise::{
    transport_nonce, Error as NoiseError, HandshakeResult, Initiator, InitiationInfo, KeyPair,
    Responder, MSG1_BEFORE_MAC1, MSG1_SIZE, MSG2_BEFORE_MAC1, MSG2_SIZE,
};
