#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = notecrypt_format::decode_tree(data, &notecrypt_format::DecodeLimits::PHASE_1); });
