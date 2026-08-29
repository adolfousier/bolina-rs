//! W5 daemon smoke tests — verify modules compile
#[test]
fn daemon_module_compiles() {
    use bolina::daemon;
    let _ = std::any::type_name::<daemon::Daemon>();
}

#[test]
fn control_module_compiles() {
    use bolina::control;
    let _ = std::any::type_name::<control::ControlPlane>();
}

#[test]
fn transport_modules_compile() {
    use bolina::transport::{noise, session, relay};
    let _ = std::any::type_name::<noise::Initiator>();
    let _ = std::any::type_name::<session::Session>();
    let _ = std::any::type_name::<relay::RelayRegistration>();
}

#[test]
fn state_modules_compile() {
    use bolina::state::{GrantLedger, intent};
    let _ = std::any::type_name::<GrantLedger>();
    let _ = std::any::type_name::<intent::Table>();
}

#[test]
fn ca_module_compiles() {
    use bolina::ca;
    let _ = std::any::type_name::<ca::IssueResult>();
}

#[test]
fn codec_module_compiles() {
    use bolina::codec;
    let _ = std::any::type_name::<codec::Envelope>();
}
