//! main.rs — entry point + env config + boot order (W12 task-8 wiring).
//!
//! Port of src/main.zig boot order. The bin is thin: everything comes from
//! the bolina lib (single compile, no bin-context module duplication).
//!   1. Env config (BOLINA_BIND, BOLINA_DATA_DIR)
//!   2. Keys load-or-generate (D-018); tamper is fatal
//!   3. Daemon init + ledger attach (corrupt log fatal, never truncated)
//!   4. BOLINA_RESOURCES: declared canonicals, fatal on refusal (BE-RES-02,
//!      fail-closed: without it the node admits nothing, D-091)
//!   5. Control plane (BOLINA_CONTROL) + bearer token (print-once, F7)

use std::net::SocketAddr;
use std::path::Path;

use bolina::daemon::{install_shutdown_handler, Daemon};
use bolina::keys;
use bolina::transport::token;

const DEFAULT_BIND: &str = "0.0.0.0:7420";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn fatal(msg: &str) -> ! {
    eprintln!("bolina: fatal: {msg}");
    std::process::exit(1);
}

fn hex_enc(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // 1. Env config
    if std::env::var("BOLINA_TEST_CA").is_ok() {
        fatal("BOLINA_TEST_CA is dev-only; test pilots mint their CA in-process");
    }
    let bind_spec = env_or("BOLINA_BIND", DEFAULT_BIND);
    let bind: SocketAddr = bind_spec.parse().unwrap_or_else(|_| {
        fatal(&format!(
            "unparseable BOLINA_BIND '{bind_spec}' (want a.b.c.d:port)"
        ));
    });

    let data_dir = env_or("BOLINA_DATA_DIR", "~/.bolina");
    let data_path = shellexpand::tilde(&data_dir).to_string();

    // 2. Keys load-or-generate (D-018)
    let node_keys = keys::load_or_generate(Path::new(&data_path))
        .unwrap_or_else(|e| fatal(&format!("key material under {data_path}: {e:?}")));
    let sig_pub = node_keys.sig_pub();
    // fingerprint DELEGATES to executor_fp (BE-RES-06): this printed fp is
    // exactly what BOLINA_RESOURCES canonicals must embed (bol:<fp>/ns/name).
    // fingerprint returns rendered hex (16 ASCII chars) - print it directly.
    println!(
        "bolina: identity fingerprint {}",
        String::from_utf8_lossy(&keys::fingerprint(&sig_pub))
    );
    println!("bolina: kex pub {}", hex_enc(&node_keys.pub_static));
    println!("bolina: sig pub {}", hex_enc(&sig_pub));
    // harness-facing aliases (g4 wrapper greps these exact keys)
    println!("daemon_kex_pub={}", hex_enc(&node_keys.pub_static));
    println!("daemon_sig_pub={}", hex_enc(&sig_pub));

    // 3. Daemon init + ledger
    let mut daemon = Daemon::new(bind, node_keys);
    let ledger_path =
        std::env::var("BOLINA_LEDGER").unwrap_or_else(|_| format!("{data_path}/ledger.bin"));
    daemon
        .attach_ledger(Path::new(&ledger_path))
        .unwrap_or_else(|e| fatal(&format!("ledger at {ledger_path}: {e}")));
    println!("bolina: ledger attached at {ledger_path}");

    // 4. Declared resources (BE-RES-02): comma-separated canonical ids
    if let Ok(res_list) = std::env::var("BOLINA_RESOURCES") {
        for raw in res_list.split(',') {
            let name = raw.trim();
            if name.is_empty() {
                continue;
            }
            daemon.add_resource(name).unwrap_or_else(|e| fatal(&e));
        }
        println!("bolina: resources declared");
    }

    // 5. Control plane + bearer token (print-once contract)
    if let Ok(control_spec) = std::env::var("BOLINA_CONTROL") {
        let control_addr: SocketAddr = control_spec.parse().unwrap_or_else(|_| {
            fatal(&format!("unparseable BOLINA_CONTROL '{control_spec}'"));
        });
        daemon
            .attach_control(control_addr)
            .unwrap_or_else(|e| fatal(&format!("control plane {control_addr}: {e}")));
        let token_path = format!("{data_path}/control.token");
        let tok = match token::load(&token_path) {
            Some(raw) => token::hex(&raw),
            None => {
                let raw = token::generate();
                token::save(&token_path, &raw).unwrap_or_else(|e| {
                    fatal(&format!("control token save under {data_path}: {e:?}"))
                });
                let hexed = token::hex(&raw);
                println!(
                    "bolina: control plane token {} (printed once; stored at {token_path})",
                    String::from_utf8_lossy(&hexed)
                );
                hexed
            }
        };
        daemon.token = Some(tok);
        println!("bolina: control plane attached on {control_addr}");
    }

    // 6. Signal handler + run loop
    install_shutdown_handler();
    println!("bolina: running");
    daemon
        .run_loop()
        .unwrap_or_else(|e| fatal(&format!("run loop: {e}")));
    println!("bolina: shutdown complete, ledger consistent");
}
