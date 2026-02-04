//! Command implementations.

pub mod config;
pub mod count;
pub mod defend;
pub mod dns;
pub mod host;
pub mod myip;
pub mod search;
pub mod threat;

use crate::output::OutputFormat;

/// Shared context for all commands.
#[derive(Debug, Clone)]
pub struct Context {
    /// Shodan API key
    pub shodan_key: Option<String>,

    /// Censys API ID
    pub censys_id: Option<String>,

    /// Censys API secret
    pub censys_secret: Option<String>,

    /// Criminal IP API key
    pub criminalip_key: Option<String>,

    /// Output format
    pub output_format: OutputFormat,

    /// Whether to show educational explanations
    pub explain: bool,

    /// Verbose output
    pub verbose: bool,

    /// Disable colors
    pub no_color: bool,
}

impl Context {
    /// Get the Shodan API key, returning an error if not set.
    pub fn require_shodan_key(&self) -> anyhow::Result<&str> {
        self.shodan_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "Shodan API key required.\n\n\
                 Set it with one of:\n  \
                 1. --api-key <KEY>\n  \
                 2. SHODAN_API_KEY or I1_SHODAN_KEY environment variable\n  \
                 3. i1 config set shodan-key <KEY>\n\n\
                 Get your key at: https://account.shodan.io"
            )
        })
    }

    /// Create a Shodan provider with the configured API key.
    pub fn shodan_provider(&self) -> anyhow::Result<i1::ShodanProvider> {
        let key = self.require_shodan_key()?;
        Ok(i1::ShodanProvider::new(key))
    }

    /// Check if any provider is configured.
    pub const fn has_any_provider(&self) -> bool {
        self.shodan_key.is_some()
            || (self.censys_id.is_some() && self.censys_secret.is_some())
            || self.criminalip_key.is_some()
    }
}
