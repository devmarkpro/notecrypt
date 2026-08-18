#[test]
fn protected_format_values_do_not_offer_equality_capabilities() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/compile_fail/*.rs");
}
