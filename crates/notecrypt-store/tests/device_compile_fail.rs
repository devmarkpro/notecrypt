#![cfg(feature = "test-support")]

#[test]
fn device_inputs_candidates_and_capabilities_are_opaque_and_linear() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/device_*.rs");
}
