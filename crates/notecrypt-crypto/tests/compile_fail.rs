#[test]
fn secret_and_envelope_capabilities_cannot_escape_through_common_traits() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/compile_fail/*.rs");
}
