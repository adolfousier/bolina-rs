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
pub mod dag;
pub mod evidence;
pub mod historical;
pub mod grant_trace;
pub mod token;
pub mod render;
pub mod relay_store;
pub mod replay;
pub mod listener;
pub mod binding;

pub mod handshake;
