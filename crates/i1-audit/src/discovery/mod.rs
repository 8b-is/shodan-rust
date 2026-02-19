//! System discovery — binaries, processes, and root certificates.

pub mod binaries;
pub mod certs;

// procfs-based process discovery (Linux only)
#[cfg(target_os = "linux")]
pub mod processes;

// Cross-platform fallback using std/command
#[cfg(not(target_os = "linux"))]
pub mod processes_fallback;

pub use binaries::{correlate_processes, discover_binaries, DEFAULT_BIN_PATHS};
pub use certs::discover_root_certs;

#[cfg(target_os = "linux")]
pub use processes::{discover_processes, get_cpu_count, get_system_uptime};

#[cfg(not(target_os = "linux"))]
pub use processes_fallback::{discover_processes, get_cpu_count, get_system_uptime};
