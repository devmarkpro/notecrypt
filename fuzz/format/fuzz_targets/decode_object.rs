#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let limits = notecrypt_format::DecodeLimits::PHASE_1;
    let _ = notecrypt_format::decode_aead_object(data, &limits);
    let _ = notecrypt_format::decode_snapshot_object(data, &limits);
    let _ = notecrypt_format::decode_content_chunk(data, &limits);
    let _ = notecrypt_format::decode_head(data, &limits);
    let _ = notecrypt_format::decode_local_state(data, &limits);
});
