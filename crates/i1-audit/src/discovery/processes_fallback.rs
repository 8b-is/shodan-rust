//! Cross-platform process discovery fallback (macOS, etc.).
//!
//! Uses `ps` and `sysctl` instead of `/proc`.

use std::process::Command;
use std::time::SystemTime;

use tracing::debug;

use crate::error::{AuditError, Result};
use crate::types::{ProcessInfo, UsageMetric};

/// Discover running processes via `ps`.
///
/// # Errors
///
/// Returns `AuditError::Process` if `ps` fails.
pub fn discover_processes() -> Result<Vec<ProcessInfo>> {
    let system_uptime = get_system_uptime()?;
    let cpu_count = get_cpu_count();

    // ps -axo pid,uid,etime,pcpu,comm — portable across macOS and BSDs
    let output = Command::new("ps")
        .args(["-axo", "pid=,uid=,etime=,pcpu=,comm="])
        .output()
        .map_err(|e| AuditError::Process(format!("failed to run ps: {e}")))?;

    if !output.status.success() {
        return Err(AuditError::Process(
            "ps exited with non-zero status".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();

    for line in stdout.lines() {
        match parse_ps_line(line, system_uptime, cpu_count) {
            Ok(info) => processes.push(info),
            Err(e) => {
                debug!(error = %e, line = %line.trim(), "skipping ps line");
            }
        }
    }

    Ok(processes)
}

/// Parse a single line of `ps -axo pid=,uid=,etime=,pcpu=,comm=` output.
fn parse_ps_line(
    line: &str,
    system_uptime: u64,
    cpu_count: u32,
) -> Result<ProcessInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(AuditError::Process(format!(
            "unexpected ps format: {line}"
        )));
    }

    let pid = parts[0]
        .parse::<i32>()
        .map_err(|e| AuditError::Process(format!("bad pid: {e}")))?;
    let uid = parts[1]
        .parse::<u32>()
        .map_err(|e| AuditError::Process(format!("bad uid: {e}")))?;
    let etime = parts[2];
    let cpu_pct: f64 = parts[3]
        .parse()
        .map_err(|e| AuditError::Process(format!("bad cpu%: {e}")))?;
    // comm may contain spaces; rejoin everything from index 4 onward
    let name = parts[4..].join(" ");

    let program_uptime_secs = parse_etime(etime);
    let avg_cpu = cpu_pct / 100.0;

    let usage = UsageMetric::compute(
        program_uptime_secs,
        system_uptime,
        avg_cpu,
        f64::from(cpu_count),
    );

    Ok(ProcessInfo {
        pid,
        name,
        exe_path: None, // not easily available from ps
        cmdline: Vec::new(),
        uid,
        usage,
    })
}

/// Parse elapsed time from ps format: [[dd-]hh:]mm:ss
fn parse_etime(s: &str) -> u64 {
    let mut total: u64 = 0;

    // Split on '-' first for days
    let (days, rest) = if let Some((d, r)) = s.split_once('-') {
        (d.parse::<u64>().unwrap_or(0), r)
    } else {
        (0, s)
    };
    total += days * 86400;

    // Split remaining on ':'
    let parts: Vec<&str> = rest.split(':').collect();
    match parts.len() {
        3 => {
            total += parts[0].parse::<u64>().unwrap_or(0) * 3600;
            total += parts[1].parse::<u64>().unwrap_or(0) * 60;
            total += parts[2].parse::<u64>().unwrap_or(0);
        }
        2 => {
            total += parts[0].parse::<u64>().unwrap_or(0) * 60;
            total += parts[1].parse::<u64>().unwrap_or(0);
        }
        1 => {
            total += parts[0].parse::<u64>().unwrap_or(0);
        }
        _ => {}
    }

    total
}

/// Get system uptime in seconds.
///
/// # Errors
///
/// Returns `AuditError::Process` if uptime cannot be determined.
pub fn get_system_uptime() -> Result<u64> {
    // macOS: sysctl kern.boottime
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output()
            .map_err(|e| AuditError::Process(format!("sysctl failed: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: { sec = 1234567890, usec = 0 } ...
        if let Some(sec_str) = stdout
            .split("sec = ")
            .nth(1)
            .and_then(|s| s.split(',').next())
        {
            let boot_secs: u64 = sec_str
                .trim()
                .parse()
                .map_err(|e| AuditError::Process(format!("bad boot time: {e}")))?;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            return Ok(now.saturating_sub(boot_secs));
        }

        Err(AuditError::Process(
            "could not parse kern.boottime".to_string(),
        ))
    }

    // Fallback for other platforms
    #[cfg(not(target_os = "macos"))]
    {
        Err(AuditError::Process(
            "uptime not supported on this platform".to_string(),
        ))
    }
}

/// Get number of CPU cores.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn get_cpu_count() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}
