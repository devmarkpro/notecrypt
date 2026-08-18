#[test]
fn unlocked_sessions_and_leases_are_opaque_and_noncopyable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/local_*.rs");
}
