//! W12 integration harness client.
//!
//! Exercises the bolina daemon over the real execution path: Noise_IK
//! handshake, binding frame, encrypted envelopes (wire path), and the
//! control API (HTTP path). Design + ladder + wiring-validation matrix:
//! `docs/w12-integration-harness-design.md`.
//!
//! Rung E (design section 5.1): pass `--zig` to target the sealed Zig
//! daemon v0.6.1 (owner's machine). Same client, different responder -
//! this is the symmetry-trap check that caught the W4 msg1 bug.

mod handshake;
mod keys;
mod ladder_a;
mod ladder_b;
mod ladder_c;
mod ladder_d;
mod ladder_e;

use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use crate::keys::{seeded, ClientKeys};

struct Args {
    daemon: SocketAddr,
    control: SocketAddr,
    seed: u64,
    round: u32,
    zig: bool,
    daemon_kex_pub: [u8; 32],
    daemon_sig_pub: [u8; 32],
    timeout_ms: u64,
    canonical: String,
    control_token: Option<String>,
    ladder: char,
}

fn usage() -> String {
    String::from(
        "integration-client - W12 harness client (design: docs/w12-integration-harness-design.md)\n\
         \n\
         USAGE:\n\
         \x20   integration-client [FLAGS]\n\
         \n\
         FLAGS:\n\
         \x20   --daemon <ip:port>      Rust daemon wire endpoint, UDP (required)\n\
         \x20   --control <ip:port>     daemon control API endpoint, TCP (required)\n\
         \x20   --seed <u64>            round seed; keys derive deterministically (required)\n\
         \x20   --round <u32>           round number for the soak log (default 0)\n\
         \x20   --daemon-kex-pub <hex>  responder X25519 static pub, 64 hex chars (required)\n\
         \x20   --daemon-sig-pub <hex>  responder Ed25519 sig pub, 64 hex chars (required)\n\
         \x20   --zig                   rung E: target the Zig daemon v0.6.1 (symmetry check)\n\
         \x20   --ladder <a|b|c|d>      which ladder to run (default a)\n\
         \x20   --timeout-ms <u64>      per-step wire timeout, milliseconds (default 2000)\n\
         \x20   --help                  show this help\n\
         \n\
         Determinism: same --seed produces identical client keys and fingerprint.\n\
         Exit code: 0 = ladder completed, 1 = step failed, 2 = bad args.",
    )
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{what}: invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{what}: expected 64 hex chars, got {}", s.len()))
}

fn parse_addr(s: &str, what: &str) -> Result<SocketAddr, String> {
    SocketAddr::from_str(s).map_err(|e| format!("{what}: {e}"))
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        daemon: SocketAddr::from_str("127.0.0.1:9800").unwrap(),
        control: SocketAddr::from_str("127.0.0.1:9801").unwrap(),
        seed: 0,
        round: 0,
        zig: false,
        daemon_kex_pub: [0u8; 32],
        daemon_sig_pub: [0u8; 32],
        timeout_ms: 2_000,
        canonical: "bol:0000000000000000/ns/dev/x".to_string(),
        control_token: None,
        ladder: 'a',
    };
    let mut have_daemon = false;
    let mut have_control = false;
    let mut have_kex = false;
    let mut have_sig = false;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag}: missing value"));
        match flag.as_str() {
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            "--print-ca" => {
                // harness harvest mode: print the seeded identity's CA pub
                // (hex64) and exit; the wrapper installs it as ca0.pub so the
                // daemon trusts the client's binding certs (task-8 wiring)
                let ck: ClientKeys = seeded(args.seed);
                println!("client_ca_pub={}", hex::encode(ck.ca.verifying_key().to_bytes()));
                std::process::exit(0);
            }
            "--daemon" => {
                args.daemon = parse_addr(&value()?, "--daemon")?;
                have_daemon = true;
            }
            "--control" => {
                args.control = parse_addr(&value()?, "--control")?;
                have_control = true;
            }
            "--seed" => args.seed = value()?.parse().map_err(|_| "--seed: expected u64")?,
            "--round" => args.round = value()?.parse().map_err(|_| "--round: expected u32")?,
            "--daemon-kex-pub" => {
                args.daemon_kex_pub = parse_hex32(&value()?, "--daemon-kex-pub")?;
                have_kex = true;
            }
            "--daemon-sig-pub" => {
                args.daemon_sig_pub = parse_hex32(&value()?, "--daemon-sig-pub")?;
                have_sig = true;
            }
            "--zig" => args.zig = true,
            "--ladder" => {
                let v = value()?;
                let c = v.chars().next().ok_or("--ladder: empty")?.to_ascii_lowercase();
                if !matches!(c, 'a' | 'b' | 'c' | 'd' | 'e') {
                    return Err(format!("--ladder: unknown ladder '{v}' (a|b|c|d)"));
                }
                args.ladder = c;
            }
            "--canonical" => {
                args.canonical = value()?.to_string();
            }
            "--timeout-ms" => {
                args.timeout_ms = value()?.parse().map_err(|_| "--timeout-ms: expected u64")?
            }
            "--control-token" => {
                args.control_token = Some(value()?);
            }
            other => return Err(format!("unknown flag: {other} (see --help)")),
        }
    }

    for (have, what) in [
        (have_daemon, "--daemon"),
        (have_control, "--control"),
        (have_kex, "--daemon-kex-pub"),
        (have_sig, "--daemon-sig-pub"),
    ] {
        if !have {
            return Err(format!("{what} is required (see --help)"));
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let ck: ClientKeys = seeded(args.seed);
    let sig_pub = ck.sig.verifying_key().to_bytes();
    let fp = String::from_utf8_lossy(&bolina::keys::fingerprint(&sig_pub)).into_owned();
    let target = if args.zig { "zig-v0.6.1" } else { "rust" };

    println!(
        "round={} seed={} target={target} client_fp={fp} client_kex={}",
        args.round,
        args.seed,
        hex::encode(ck.kex.public),
    );
    // Task-8 wiring consumes these: daemon trust set + resolver entries.
    println!(
        "client_ca_pub={} client_approver_pub={}",
        hex::encode(ck.ca.verifying_key().to_bytes()),
        hex::encode(ck.approver.verifying_key().to_bytes()),
    );

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: udp bind failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(args.timeout_ms))) {
        eprintln!("error: set_read_timeout: {e}");
        return ExitCode::FAILURE;
    }

    let log = match args.ladder {
        'a' => ladder_a::run(&socket, args.daemon, &ck, args.daemon_kex_pub, args.daemon_sig_pub, args.seed, args.round, args.zig),
        'b' => ladder_b::run(&socket, args.daemon, &ck, args.daemon_kex_pub, args.daemon_sig_pub, args.seed, args.round, args.zig),
        'c' => ladder_c::run(&socket, args.daemon, &ck, args.daemon_kex_pub, args.daemon_sig_pub, args.round, args.zig),
        'e' => ladder_e::run(&socket, args.daemon, args.daemon_kex_pub, args.daemon_sig_pub, args.round, args.control, args.control_token.as_deref(), Duration::from_millis(args.timeout_ms)),
        'd' => ladder_d::run(&socket, args.daemon, &ck, args.daemon_kex_pub, args.daemon_sig_pub, args.seed, args.round, args.control, &args.canonical, args.control_token.as_deref(), Duration::from_millis(args.timeout_ms)),
        other => {
            eprintln!("error: ladder '{other}' not implemented yet");
            return ExitCode::from(2);
        }
    };

    // Round log: frozen= declaration first (acceptance criterion), steps after.
    println!("{}", log.frozen);
    for (step, msg) in &log.steps {
        println!("  {step}: {msg}");
    }
    if log.ok {
        println!("round result: PASS ({} steps)", log.steps.len());
        ExitCode::SUCCESS
    } else {
        println!(
            "round result: FAIL at {} ({} steps)",
            log.failed_at.unwrap_or("?"),
            log.steps.len()
        );
        ExitCode::FAILURE
    }
}
