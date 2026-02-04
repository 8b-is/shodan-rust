//! Command-line argument definitions using clap.

use crate::output::OutputFormat;
use clap::{Args, Parser, Subcommand};

/// i1 - Security Operations CLI
///
/// Multi-provider threat intelligence at your fingertips.
/// Supports Shodan, Censys, Criminal IP, and i1.is native providers.
///
/// Get API keys at:
///   - Shodan: <https://account.shodan.io>
///   - Censys: <https://search.censys.io/account/api>
///   - Criminal IP: <https://www.criminalip.io/mypage/information>
#[derive(Parser, Debug)]
#[command(name = "i1")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Primary API key (Shodan by default, or set `I1_SHODAN_KEY`)
    #[arg(short = 'k', long, env = "SHODAN_API_KEY", global = true)]
    pub api_key: Option<String>,

    /// Output format
    #[arg(short, long, global = true, value_enum)]
    pub output: Option<OutputFormat>,

    /// Explain what this command does
    #[arg(long, global = true)]
    pub explain: bool,

    /// Increase verbosity
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Which provider to use (shodan, censys, criminalip, native, all)
    #[arg(short, long, global = true, default_value = "shodan")]
    pub provider: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Look up information about a specific IP address
    Host(HostArgs),

    /// Search threat intelligence database
    Search(SearchArgs),

    /// Count results without using query credits
    Count(CountArgs),

    /// DNS lookups and domain information
    Dns(DnsArgs),

    /// Show your public IP address
    Myip,

    /// Defensive tools: geo-blocking, IP bans, firewall rules
    Defend(DefendArgs),

    /// Manage CLI configuration
    Config(ConfigArgs),

    /// Quick threat response: lookup + optional ban in one command
    #[command(alias = "t")]
    Threat(ThreatArgs),
}

// ============================================================================
// Host command
// ============================================================================

#[derive(Args, Debug)]
pub struct HostArgs {
    /// IP address to look up
    pub ip: String,

    /// Query all configured providers
    #[arg(long)]
    pub all: bool,
}

// ============================================================================
// Threat command - quick response: lookup + ban
// ============================================================================

#[derive(Args, Debug)]
pub struct ThreatArgs {
    /// IP address to investigate
    pub ip: String,

    /// Automatically ban the IP after lookup
    #[arg(long, short)]
    pub ban: bool,

    /// Also ban the entire AS number
    #[arg(long, short = 'a')]
    pub ban_asn: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Generate and show iptables command to run
    #[arg(long, short = 'x')]
    pub execute: bool,
}

// ============================================================================
// Search command
// ============================================================================

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Search query (e.g., "apache country:US port:80")
    pub query: String,

    /// Page number (1-indexed)
    #[arg(short, long, default_value = "1")]
    pub page: u32,
}

// ============================================================================
// Count command
// ============================================================================

#[derive(Args, Debug)]
pub struct CountArgs {
    /// Query to count
    pub query: String,
}

// ============================================================================
// DNS command
// ============================================================================

#[derive(Args, Debug)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub command: DnsCommands,
}

#[derive(Subcommand, Debug)]
pub enum DnsCommands {
    /// Resolve hostname to IP addresses
    Resolve {
        /// Hostname to resolve
        hostname: String,
    },

    /// Reverse DNS lookup
    Reverse {
        /// IP address
        ip: String,
    },
}

// ============================================================================
// Defend command
// ============================================================================

#[derive(Args, Debug)]
pub struct DefendArgs {
    #[command(subcommand)]
    pub command: DefendCommands,
}

#[derive(Subcommand, Debug)]
pub enum DefendCommands {
    /// Show current blocking status
    Status {
        /// Quick one-line summary
        #[arg(long, short)]
        quick: bool,
    },

    /// Manage country-level geo-blocking
    Geoblock(GeoblockArgs),

    /// Ban an IP address or CIDR range
    Ban {
        /// IP address or CIDR to block
        target: String,

        /// Treat target as AS number
        #[arg(long, short = 'a')]
        as_number: bool,

        /// Show what would happen without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Remove an IP or AS from the block list
    Unban {
        /// IP address, CIDR, or AS number to unblock
        target: String,
    },

    /// Manage whitelist (IPs that are never blocked)
    Whitelist(WhitelistArgs),

    /// Export firewall rules
    Export {
        /// Output format: nftables, iptables, pf
        #[arg(long, default_value = "nftables")]
        format: String,
    },

    /// Import IPs from file or stdin
    Import {
        /// Read from stdin
        #[arg(long)]
        stdin: bool,

        /// Read from file
        #[arg(long)]
        file: Option<String>,
    },

    /// Undo the last change
    Undo,

    /// Emergency disable all blocking
    Disable,

    /// Push blocks to remote servers via SSH
    Push(PushArgs),

    /// Pull blocks from a remote server via SSH
    Pull(PullArgs),

    /// Community threat intelligence sharing
    Community(CommunityArgs),
}

#[derive(Args, Debug)]
pub struct CommunityArgs {
    #[command(subcommand)]
    pub command: CommunityCommands,
}

#[derive(Subcommand, Debug)]
pub enum CommunityCommands {
    /// Contribute your blocked IPs to the community
    Contribute {
        /// Include fail2ban blocks
        #[arg(long, short)]
        fail2ban: bool,

        /// Minimum times an IP must be blocked to contribute (default: 3)
        #[arg(long, default_value = "3")]
        min_hits: u32,

        /// Show what would be contributed without sending
        #[arg(long)]
        dry_run: bool,
    },

    /// Fetch community blocklist
    Fetch {
        /// Minimum reports before including (default: 5)
        #[arg(long, default_value = "5")]
        min_reports: u32,

        /// Merge with existing (default: true)
        #[arg(long)]
        replace: bool,

        /// Show what would be fetched without saving
        #[arg(long)]
        dry_run: bool,
    },

    /// Set up automatic sync via cron
    Subscribe {
        /// Sync interval in hours (default: 6)
        #[arg(long, default_value = "6")]
        interval: u32,

        /// Remove the cron job
        #[arg(long)]
        remove: bool,
    },

    /// Show community stats
    Stats,
}

#[derive(Args, Debug)]
pub struct PullArgs {
    /// Host from SSH config to pull from
    pub host: String,

    /// Merge with existing blocks (default: replace)
    #[arg(long, short)]
    pub merge: bool,

    /// Show what would be pulled without saving
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct PushArgs {
    /// Specific hosts from SSH config (comma-separated or multiple -H flags)
    #[arg(short = 'H', long = "host", value_delimiter = ',')]
    pub hosts: Option<Vec<String>>,

    /// Push to all hosts in SSH config
    #[arg(long, short)]
    pub all: bool,

    /// Show what would be pushed without executing
    #[arg(long)]
    pub dry_run: bool,

    /// Only push IPs blocked since this command (not full list)
    #[arg(long)]
    pub incremental: bool,
}

#[derive(Args, Debug)]
pub struct GeoblockArgs {
    #[command(subcommand)]
    pub command: GeoblockCommands,
}

#[derive(Subcommand, Debug)]
pub enum GeoblockCommands {
    /// List currently blocked countries
    List,

    /// Block countries by code (e.g., cn ru)
    Add {
        /// Country codes to block
        countries: Vec<String>,

        /// Show what would happen without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Unblock a country
    Remove {
        /// Country code to unblock
        country: String,
    },

    /// Update IP ranges from upstream
    Update,

    /// Show country code reference
    Codes,
}

#[derive(Args, Debug)]
pub struct WhitelistArgs {
    #[command(subcommand)]
    pub command: WhitelistCommands,
}

#[derive(Subcommand, Debug)]
pub enum WhitelistCommands {
    /// Show whitelisted IPs
    Show,

    /// Add IP to whitelist
    Add {
        /// IP address to whitelist
        ip: String,
    },

    /// Remove IP from whitelist
    Remove {
        /// IP address to remove
        ip: String,
    },
}

// ============================================================================
// Config command
// ============================================================================

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set a configuration value
    Set {
        /// Key to set (e.g., shodan-key, censys-id)
        key: String,

        /// Value to set
        value: String,
    },

    /// Show config file path
    Path,
}
