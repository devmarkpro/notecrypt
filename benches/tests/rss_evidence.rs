use notecrypt_benches::rss::{
    RssEvidence, parse_linux_status_bytes, parse_macos_time_peak_rss, parse_process_bytes,
    parse_ps_rss_bytes,
};

#[test]
fn parses_each_supported_platform_metric_without_unit_ambiguity() {
    assert_eq!(
        parse_macos_time_peak_rss(b"  9876543  maximum resident set size\n").unwrap(),
        9_876_543,
    );
    assert_eq!(
        parse_linux_status_bytes("VmRSS:\t1234 kB\nVmHWM:\t5678 kB\n", "VmRSS").unwrap(),
        1_263_616,
    );
    assert_eq!(
        parse_linux_status_bytes("VmRSS:\t1234 kB\nVmHWM:\t5678 kB\n", "VmHWM").unwrap(),
        5_814_272,
    );
    assert_eq!(parse_ps_rss_bytes(b" 2048\n").unwrap(), 2_097_152);
    assert_eq!(parse_process_bytes(b"4194304\r\n").unwrap(), 4_194_304);
}

#[test]
fn rejects_missing_malformed_zero_and_inverted_rss_evidence() {
    assert!(parse_macos_time_peak_rss(b"no metric here").is_err());
    assert!(parse_linux_status_bytes("VmRSS: unknown kB\n", "VmRSS").is_err());
    assert!(parse_linux_status_bytes("VmRSS: 1 MB\n", "VmRSS").is_err());
    assert!(parse_ps_rss_bytes(b"0\n").is_err());
    assert!(parse_process_bytes(b"\n").is_err());
    assert!(RssEvidence::try_new(0, 1, "method").is_err());
    assert!(RssEvidence::try_new(1, 0, "method").is_err());
    assert!(RssEvidence::try_new(2, 1, "method").is_err());
    assert!(RssEvidence::try_new(1, 1, "method").is_err());
    assert!(RssEvidence::try_new(1, 1, "").is_err());
}

#[test]
fn worker_contract_cannot_serialize_missing_metrics_as_zero() {
    let evidence = RssEvidence::try_new(4_194_304, 6_291_456, "same-worker fixture").unwrap();
    let record = serde_json::json!({
        "initial_fresh_process_rss_bytes": evidence.initial_bytes,
        "peak_fresh_process_rss_bytes": evidence.peak_bytes,
        "peak_fresh_process_rss_delta_bytes": evidence.delta_bytes,
        "rss_measurement_method": evidence.measurement_method,
        "rss_measurement_available": evidence.measurement_available,
    });

    assert!(record["initial_fresh_process_rss_bytes"].as_u64().unwrap() > 0);
    assert!(record["peak_fresh_process_rss_bytes"].as_u64().unwrap() > 0);
    assert_eq!(record["peak_fresh_process_rss_delta_bytes"], 2_097_152);
    assert_eq!(record["rss_measurement_available"], true);
    assert_eq!(record["rss_measurement_method"], "same-worker fixture");
}
