//! Main boundary tests — kill mutants in env_or/parse_bind/main.

#[test]
fn parse_bind_valid_address() {
    let addr = bolina::main::parse_bind("127.0.0.1:8080");
    assert!(addr.is_some());
}

#[test]
fn parse_bind_invalid_address() {
    let addr = bolina::main::parse_bind("not-an-address");
    assert!(addr.is_none());
}

#[test]
fn parse_bind_empty_string() {
    let addr = bolina::main::parse_bind("");
    assert!(addr.is_none());
}
