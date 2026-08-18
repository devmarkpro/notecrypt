//! Strict same-worker resident-memory evidence for benchmark records.

use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub struct RssMetricError(&'static str);

impl Display for RssMetricError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for RssMetricError {}

pub struct RssEvidence {
    pub initial_bytes: u64,
    pub peak_bytes: u64,
    pub delta_bytes: u64,
    pub measurement_method: &'static str,
    pub measurement_available: bool,
}

impl RssEvidence {
    pub fn try_new(
        initial_bytes: u64,
        peak_bytes: u64,
        measurement_method: &'static str,
    ) -> Result<Self, RssMetricError> {
        if initial_bytes == 0 || peak_bytes == 0 {
            return Err(RssMetricError("RSS evidence must be non-zero"));
        }
        if measurement_method.is_empty() {
            return Err(RssMetricError("RSS measurement method must be named"));
        }
        if peak_bytes <= initial_bytes {
            return Err(RssMetricError(
                "peak RSS must exceed same-worker initial RSS",
            ));
        }
        let delta_bytes = peak_bytes
            .checked_sub(initial_bytes)
            .ok_or(RssMetricError("peak RSS is below same-worker initial RSS"))?;
        Ok(Self {
            initial_bytes,
            peak_bytes,
            delta_bytes,
            measurement_method,
            measurement_available: true,
        })
    }
}

pub fn parse_macos_time_peak_rss(stderr: &[u8]) -> Result<u64, RssMetricError> {
    let text = std::str::from_utf8(stderr)
        .map_err(|_| RssMetricError("macOS time output is not UTF-8"))?;
    let bytes = text.lines().find_map(|line| {
        line.trim()
            .strip_suffix("maximum resident set size")?
            .trim()
            .parse::<u64>()
            .ok()
    });
    require_non_zero(bytes, "macOS peak RSS is unavailable")
}

pub fn parse_linux_status_bytes(status: &str, field: &str) -> Result<u64, RssMetricError> {
    let prefix = format!("{field}:");
    let mut fields = status.lines().find_map(|line| {
        line.strip_prefix(&prefix)
            .map(|value| value.split_whitespace())
    });
    let kib = fields
        .as_mut()
        .and_then(Iterator::next)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(RssMetricError("Linux RSS value is unavailable"))?;
    if fields.as_mut().and_then(Iterator::next) != Some("kB")
        || fields.as_mut().and_then(Iterator::next).is_some()
    {
        return Err(RssMetricError("Linux RSS unit is not canonical kB"));
    }
    require_non_zero(kib.checked_mul(1_024), "Linux RSS byte conversion failed")
}

pub fn parse_ps_rss_bytes(stdout: &[u8]) -> Result<u64, RssMetricError> {
    let kib = parse_single_decimal(stdout, "ps RSS is unavailable")?;
    require_non_zero(kib.checked_mul(1_024), "ps RSS byte conversion failed")
}

pub fn parse_process_bytes(stdout: &[u8]) -> Result<u64, RssMetricError> {
    let bytes = parse_single_decimal(stdout, "process memory metric is unavailable")?;
    require_non_zero(Some(bytes), "process memory metric must be non-zero")
}

fn parse_single_decimal(bytes: &[u8], message: &'static str) -> Result<u64, RssMetricError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or(RssMetricError(message))
}

fn require_non_zero(value: Option<u64>, message: &'static str) -> Result<u64, RssMetricError> {
    match value {
        Some(value) if value > 0 => Ok(value),
        _ => Err(RssMetricError(message)),
    }
}

#[cfg(target_os = "macos")]
pub const RSS_MEASUREMENT_METHOD: &str =
    "same-worker initial ps RSS and parent /usr/bin/time -l maximum resident set size";

#[cfg(target_os = "linux")]
pub const RSS_MEASUREMENT_METHOD: &str =
    "same-worker /proc/self/status initial VmRSS and absolute VmHWM";

#[cfg(windows)]
pub const RSS_MEASUREMENT_METHOD: &str =
    "same-worker PowerShell WorkingSet64 initial and PeakWorkingSet64 peak";

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub const RSS_MEASUREMENT_METHOD: &str = "unsupported operating system";

#[cfg(target_os = "macos")]
pub fn initial_process_rss_bytes() -> Result<u64, RssMetricError> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .map_err(|_| RssMetricError("failed to execute ps for initial RSS"))?;
    if !output.status.success() {
        return Err(RssMetricError("ps failed while reading initial RSS"));
    }
    parse_ps_rss_bytes(&output.stdout)
}

#[cfg(target_os = "linux")]
pub fn initial_process_rss_bytes() -> Result<u64, RssMetricError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| RssMetricError("failed to read Linux process status"))?;
    parse_linux_status_bytes(&status, "VmRSS")
}

#[cfg(windows)]
pub fn initial_process_rss_bytes() -> Result<u64, RssMetricError> {
    run_windows_process_metric("WorkingSet64")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub fn initial_process_rss_bytes() -> Result<u64, RssMetricError> {
    Err(RssMetricError("RSS measurement is unsupported"))
}

#[cfg(target_os = "linux")]
pub fn worker_peak_rss_bytes() -> Result<u64, RssMetricError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| RssMetricError("failed to read Linux process status"))?;
    parse_linux_status_bytes(&status, "VmHWM")
}

#[cfg(windows)]
pub fn worker_peak_rss_bytes() -> Result<u64, RssMetricError> {
    run_windows_process_metric("PeakWorkingSet64")
}

#[cfg(target_os = "macos")]
pub fn worker_peak_rss_bytes() -> Result<u64, RssMetricError> {
    Err(RssMetricError("macOS peak RSS is measured by the parent"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub fn worker_peak_rss_bytes() -> Result<u64, RssMetricError> {
    Err(RssMetricError("RSS measurement is unsupported"))
}

#[cfg(windows)]
fn run_windows_process_metric(property: &str) -> Result<u64, RssMetricError> {
    let command = format!("(Get-Process -Id {}).{property}", std::process::id());
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()
        .map_err(|_| RssMetricError("failed to execute PowerShell process query"))?;
    if !output.status.success() {
        return Err(RssMetricError("PowerShell process query failed"));
    }
    parse_process_bytes(&output.stdout)
}
