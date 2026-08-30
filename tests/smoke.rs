use ntest::timeout;

#[test]
#[timeout(10000)]
fn workspace_is_alive() {
    // W0 gate: strict lints + empty wave modules build green.
    assert_eq!(2 + 2, 4);
}
