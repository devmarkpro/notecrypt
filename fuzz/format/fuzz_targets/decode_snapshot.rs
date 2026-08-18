#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = notecrypt_format::DecodeLimits::PHASE_1;
    let _ = notecrypt_format::decode_snapshot_payload(data, &limits);
    let _ = notecrypt_format::decode_head_payload(data, &limits);
    let _ = notecrypt_format::decode_local_state_payload(data, &limits);
});
