#[test]
fn cleanup_capabilities_are_linear_and_opaque() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/cleanup_*.rs");
}
