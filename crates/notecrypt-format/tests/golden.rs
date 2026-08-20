use std::{fs, path::PathBuf};

use notecrypt_format::*;

const HASHES: &[(&str, &str)] = &[
    (
        "bootstrap",
        "1d3e505e0c4acac92151b990fe157f04779576fad7c28379595c9a2bfb4915f4",
    ),
    (
        "recovery",
        "40f9ed73133f9dce41a3ec7d34da6e1671087e1b82e5dc27e9dfbd70e673e803",
    ),
    (
        "device",
        "8d8341bb1c14e893756d4507c0eba05378255e950b4f13fcf7d9055825f8301b",
    ),
    (
        "metadata",
        "2fa7530533ec04c4fe865daf988accd9c9592e6a64242a947c1a6bc27f606694",
    ),
    (
        "tree_object",
        "4c78fce209431696664c6c85ef3529b591af2a32e8e39bb61398b72d5f628f80",
    ),
    (
        "manifest_object",
        "b81ab6e177c83e516b6be3a634508dfd677d9659f9469c1a5f2fea44ea47db0b",
    ),
    (
        "snapshot_object",
        "4174d8ec047146916b99e5ebfe185633324c16c357a8a3c94c145571992f5e14",
    ),
    (
        "head",
        "603fc8c6dbe14a95f722375ad1bf346f71d0931514ba22f4eceee62789be9f8e",
    ),
    (
        "local",
        "cc40bf2c666048815160222d31269aa76852c545b4371d6c79a4966c1ae6ac33",
    ),
    (
        "content_chunk",
        "cf08d1d416d99a62c0da13e2e9f3ff00f1b8a1134cedd78f093d320570476775",
    ),
    (
        "content_payload",
        "ecfbf86c26ba67e2fbe8c2cd96e254bf42aa99a044b828660c238860e2ed683c",
    ),
    (
        "manifest_payload",
        "d786c1423413a7542320f91ce92660d6c05119be4c2703bc710a8d0b52a9d81b",
    ),
    (
        "tree_payload",
        "7c11e4bb428e05b884e64b07a8b44c528c8b1da7cfa0bd460c490da48eaafb8b",
    ),
    (
        "snapshot_payload",
        "37ffb9bf3b0d9ad7a6b0077ddb4a63fcc89828550aed2c12839ac749f603676c",
    ),
    (
        "head_payload",
        "4b0c18a720fc5af5e820bb6137bda35581e1548dee31c6f8b90f4caf84f805d6",
    ),
    (
        "local_payload",
        "31b10e973958836437e9ad29f3c714e801cf314ffbf577320e9f54df9f525eb0",
    ),
    (
        "journal_payload",
        "301fae864ac1d31898c35c2aabdf2a97e473a0fe1b900691f538b53271698215",
    ),
    (
        "journal_local",
        "274b290b32e4fb6ba2634200b41e113f16f12959f267c0be5f42b567d1f95b2d",
    ),
    (
        "availability_payload",
        "69ae6bcfc3e36133cc41a2ffa18136d648698c00d33ac6f8c402e532df37eca7",
    ),
    (
        "availability_local",
        "d83762072a8839d5dd320eb81a7bde484120c12afb54e6b4e25e46c16f5dc299",
    ),
];

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn decode_and_reencode(name: &str, bytes: &[u8]) -> Vec<u8> {
    let limits = &DecodeLimits::PHASE_1;
    match name {
        "bootstrap" => encode_bootstrap(&decode_bootstrap(bytes, limits).unwrap()).unwrap(),
        "recovery" | "device" | "metadata" | "tree_object" | "manifest_object" => {
            encode_aead_object(&decode_aead_object(bytes, limits).unwrap()).unwrap()
        }
        "snapshot_object" => {
            encode_snapshot_object(&decode_snapshot_object(bytes, limits).unwrap()).unwrap()
        }
        "head" => encode_head(&decode_head(bytes, limits).unwrap()).unwrap(),
        "local" | "journal_local" | "availability_local" => {
            encode_local_state(&decode_local_state(bytes, limits).unwrap()).unwrap()
        }
        "content_chunk" => {
            encode_content_chunk(&decode_content_chunk(bytes, limits).unwrap()).unwrap()
        }
        "content_payload" => {
            encode_content_payload(&decode_content_payload(bytes, limits).unwrap()).unwrap()
        }
        "manifest_payload" => encode_manifest(&decode_manifest(bytes, limits).unwrap()).unwrap(),
        "tree_payload" => encode_tree(&decode_tree(bytes, limits).unwrap()).unwrap(),
        "snapshot_payload" => {
            encode_snapshot_payload(&decode_snapshot_payload(bytes, limits).unwrap()).unwrap()
        }
        "head_payload" => {
            encode_head_payload(&decode_head_payload(bytes, limits).unwrap()).unwrap()
        }
        "local_payload" | "journal_payload" | "availability_payload" => {
            encode_local_state_payload(&decode_local_state_payload(bytes, limits).unwrap()).unwrap()
        }
        _ => panic!("unknown fixture {name}"),
    }
}

#[test]
fn v1_fixtures_and_hashes_are_immutable() {
    assert_eq!(HASHES.len(), 20, "every v1 schema requires a locked hash");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    for (name, expected_hash) in HASHES {
        let fixture = fs::read_to_string(root.join(format!("{name}.hex"))).unwrap();
        let bytes = unhex(fixture.trim());
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            *expected_hash,
            "format-version decision required to replace {name}"
        );
        assert_eq!(
            decode_and_reencode(name, &bytes),
            bytes,
            "format-version decision required to replace {name}"
        );
    }
}
