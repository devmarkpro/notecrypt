use std::{collections::BTreeSet, fs, path::PathBuf};

const EXPECTED: [&str; 5] = [
    "decode_header",
    "decode_object",
    "decode_manifest",
    "decode_tree",
    "decode_snapshot",
];

#[test]
fn root_inventory_and_format_fuzz_bins_match_bidirectionally() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let public_decoders = fs::read_to_string(root.join("crates/notecrypt-format/src/lib.rs"))
        .unwrap()
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|identifier| identifier.starts_with("decode_"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert!(!public_decoders.is_empty());
    let inventory: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("fuzz/targets.toml")).unwrap()).unwrap();
    assert_eq!(inventory["toolchain"].as_str(), Some("nightly-2026-08-01"));
    assert_eq!(inventory["cargo_fuzz"].as_str(), Some("0.13.1"));
    let targets = inventory["target"].as_array().unwrap();
    assert_eq!(targets.len(), EXPECTED.len());
    let raw_names = targets
        .iter()
        .map(|target| target["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    for expected in EXPECTED {
        assert_eq!(
            raw_names.iter().filter(|name| **name == expected).count(),
            1
        );
    }
    for target in targets {
        assert_eq!(target["tree"].as_str(), Some("format"));
        assert_eq!(target["project_dir"].as_str(), Some("fuzz/format"));
        assert_eq!(target["owner"].as_str(), Some("notecrypt-format"));
        assert_eq!(target["bounds"].as_str(), Some("DecodeLimits::PHASE_1"));
        let source = fs::read_to_string(root.join(format!(
            "fuzz/format/fuzz_targets/{}.rs",
            target["name"].as_str().unwrap()
        )))
        .unwrap();
        assert!(source.contains("DecodeLimits::PHASE_1"));
        let owned = target["parser"]
            .as_str()
            .unwrap()
            .split(',')
            .collect::<Vec<_>>();
        for decoder in &public_decoders {
            let call = format!("notecrypt_format::{decoder}(");
            let expected_calls = usize::from(owned.contains(&decoder.as_str()));
            assert_eq!(
                source.matches(&call).count(),
                expected_calls,
                "source ownership mismatch for durable decoder {decoder}"
            );
        }
    }
    let owned_decoders = targets
        .iter()
        .flat_map(|target| target["parser"].as_str().unwrap().split(','))
        .collect::<Vec<_>>();
    assert_eq!(owned_decoders.len(), public_decoders.len());
    for expected in &public_decoders {
        assert_eq!(
            owned_decoders
                .iter()
                .filter(|decoder| **decoder == expected)
                .count(),
            1,
            "durable decoder {expected} must have exactly one fuzz owner"
        );
    }
    let owned_decoder_set = owned_decoders
        .iter()
        .map(|decoder| (*decoder).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(owned_decoder_set, public_decoders);

    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("fuzz/format/Cargo.toml")).unwrap()).unwrap();
    assert_eq!(
        manifest["package"]["metadata"]["cargo-fuzz"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["package"]["metadata"]["cargo-fuzz-version"].as_str(),
        Some("=0.13.1")
    );
    assert_eq!(manifest["bin"].as_array().unwrap().len(), EXPECTED.len());
    let raw_bins = manifest["bin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|bin| bin["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    for expected in EXPECTED {
        assert_eq!(raw_bins.iter().filter(|name| **name == expected).count(), 1);
    }

    let source_names = fs::read_dir(root.join("fuzz/format/fuzz_targets"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| path.file_stem().unwrap().to_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let inventory_names = raw_names
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let bin_names = raw_bins
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(source_names, inventory_names);
    assert_eq!(source_names, bin_names);

    let toolchain: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("fuzz/format/rust-toolchain.toml")).unwrap())
            .unwrap();
    assert_eq!(
        toolchain["toolchain"]["channel"].as_str(),
        Some("nightly-2026-08-01")
    );
}
