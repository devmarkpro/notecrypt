#![cfg(feature = "test-support")]

#[test]
fn reachability_capabilities_are_not_forgeable_or_reusable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/reachability_*.rs");
}
