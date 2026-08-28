//! main.rs — entry point + env config + boot order
//!
//! Port of src/main.zig (269 lines). Boot order:
//! 1. CLI dispatch (ca subcommands)
//! 2. Env config (BOLINA_BIND, BOLINA_DATA_DIR, etc.)
//! 3. Keys load-or-generate (D-018)
//! 4. Ledger attach
//! 5. Control plane attach (optional)
//! 6. Run loop with signal handling

use std::env;
use std::net::SocketAddr;

mod ca;
mod codec;
mod crypto;
mod daemon;
mod control;
mod state;
mod transport;

use daemon::{Daemon, Keys, install_shutdown_handler};

const DEFAULT_BIND: &str = "0.0.0.0:7420";

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn fatal(msg: &str) -> ! {
    eprintln!("bolina: fatal: {}", msg);
    std::process::exit(1);
}

fn parse_bind(spec: &str) -> Option<SocketAddr> {
    spec.parse().ok()
}

fn main() {
    // 1. Env config
    if env::var("BOLINA_TEST_CA").is_ok() {
        fatal("BOLINA_TEST_CA is dev-only; test pilots mint their CA in-process");
    }
    let bind_spec = env_or("BOLINA_BIND", DEFAULT_BIND);
    let bind = parse_bind(&bind_spec).unwrap_or_else(|| {
        fatal(&format!("unparseable BOLINA_BIND '{}' (want a.b.c.d:port)", bind_spec));
    });

    let data_dir = env_or("BOLINA_DATA_DIR", "~/.bolina");
    let data_path = shellexpand::tilde(&data_dir).to_string();

    // 2. Keys load-or-generate (D-018)
    let keys = Keys::load_or_generate(&data_path).unwrap_or_else(|e| {
        fatal(&format!("key material under {}: {}", data_path, e));
    });
    println!("bolina: identity loaded from {}", data_path);

    // 3. Daemon init
    let mut daemon = Daemon::new(bind, keys);
    println!("bolina: daemon init on {}", bind);

    // 4. Ledger attach
    let ledger_path = env::var("BOLINA_LEDGER")
        .unwrap_or_else(|_| format!("{}/ledger.bin", data_path));
    daemon.attach_ledger(&std::path::Path::new(&ledger_path)).unwrap_or_else(|e| {
        fatal(&format!("ledger at {}: {}", ledger_path, e));
    });
    println!("bolina: ledger attached at {}", ledger_path);

    // 5. Control plane (optional)
    if let Ok(control_spec) = env::var("BOLINA_CONTROL") {
        let control_addr: SocketAddr = control_spec.parse().unwrap_or_else(|_| {
            fatal(&format!("unparseable BOLINA_CONTROL '{}'", control_spec));
        });
        daemon.attach_control(control_addr).unwrap_or_else(|e| {
            fatal(&format!("control plane {}: {}", control_addr, e));
        });
        println!("bolina: control plane attached on {}", control_addr);
    }

    // 6. Signal handler + run loop
    install_shutdown_handler();
    println!("bolina: running");
    daemon.run_loop().unwrap_or_else(|e| {
        fatal(&format!("run loop: {}", e));
    });

    println!("bolina: shutdown complete, ledger consistent");
}
