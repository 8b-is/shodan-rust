//! Command implementations.

pub mod audit;
pub mod config;
pub mod count;
pub mod defend;
pub mod dns;
pub mod host;
pub mod myip;
pub mod scan;
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

    /// Which provider to use (auto, shodan, censys, criminalip)
    pub provider: String,

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

    /// Get the best available provider for host lookups, based on --provider flag
    /// or auto-detecting from configured keys.
    pub fn host_provider(
        &self,
    ) -> anyhow::Result<Box<dyn i1_providers::HostLookup + Send + Sync>> {
        match self.provider.as_str() {
            "shodan" => Ok(Box::new(self.shodan_provider()?)),
            #[cfg(feature = "censys")]
            "censys" => {
                let id = self.censys_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Censys API ID not configured. Set I1_CENSYS_ID or i1 config set censys-id <ID>")
                })?;
                let secret = self.censys_secret.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Censys API secret not configured. Set I1_CENSYS_SECRET or i1 config set censys-secret <SECRET>")
                })?;
                Ok(Box::new(i1::CensysProvider::new(id, secret)))
            }
            #[cfg(feature = "criminalip")]
            "criminalip" => {
                let key = self.criminalip_key.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Criminal IP API key not configured. Set I1_CRIMINALIP_KEY or i1 config set criminalip-key <KEY>")
                })?;
                Ok(Box::new(i1::CriminalIpProvider::new(key)))
            }
            // "auto" or anything else: pick first configured provider
            _ => {
                if self.shodan_key.is_some() {
                    return Ok(Box::new(self.shodan_provider()?));
                }
                #[cfg(feature = "censys")]
                if self.censys_id.is_some() && self.censys_secret.is_some() {
                    return Ok(Box::new(i1::CensysProvider::new(
                        self.censys_id.as_deref().unwrap(),
                        self.censys_secret.as_deref().unwrap(),
                    )));
                }
                #[cfg(feature = "criminalip")]
                if self.criminalip_key.is_some() {
                    return Ok(Box::new(i1::CriminalIpProvider::new(
                        self.criminalip_key.as_deref().unwrap(),
                    )));
                }
                Err(anyhow::anyhow!(
                    "No API key configured.\n\n\
                     Set one with:\n  \
                     1. i1 config set shodan-key <KEY>\n  \
                     2. i1 config set censys-id <ID> + censys-secret <SECRET>\n  \
                     3. i1 config set criminalip-key <KEY>\n  \
                     4. Environment: SHODAN_API_KEY, I1_CENSYS_ID, I1_CRIMINALIP_KEY"
                ))
            }
        }
    }

    /// Get the best available search provider.
    pub fn search_provider(
        &self,
    ) -> anyhow::Result<Box<dyn i1_providers::SearchProvider + Send + Sync>> {
        match self.provider.as_str() {
            "shodan" => Ok(Box::new(self.shodan_provider()?)),
            #[cfg(feature = "censys")]
            "censys" => {
                let id = self.censys_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Censys API ID not configured.")
                })?;
                let secret = self.censys_secret.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Censys API secret not configured.")
                })?;
                Ok(Box::new(i1::CensysProvider::new(id, secret)))
            }
            #[cfg(feature = "criminalip")]
            "criminalip" => {
                let key = self.criminalip_key.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Criminal IP API key not configured.")
                })?;
                Ok(Box::new(i1::CriminalIpProvider::new(key)))
            }
            _ => {
                if self.shodan_key.is_some() {
                    return Ok(Box::new(self.shodan_provider()?));
                }
                #[cfg(feature = "censys")]
                if self.censys_id.is_some() && self.censys_secret.is_some() {
                    return Ok(Box::new(i1::CensysProvider::new(
                        self.censys_id.as_deref().unwrap(),
                        self.censys_secret.as_deref().unwrap(),
                    )));
                }
                #[cfg(feature = "criminalip")]
                if self.criminalip_key.is_some() {
                    return Ok(Box::new(i1::CriminalIpProvider::new(
                        self.criminalip_key.as_deref().unwrap(),
                    )));
                }
                Err(anyhow::anyhow!(
                    "No API key configured.\n\n\
                     Set one with:\n  \
                     1. i1 config set shodan-key <KEY>\n  \
                     2. i1 config set censys-id <ID> + censys-secret <SECRET>\n  \
                     3. i1 config set criminalip-key <KEY>"
                ))
            }
        }
    }

    /// Check if any provider is configured.
    pub const fn has_any_provider(&self) -> bool {
        self.shodan_key.is_some()
            || (self.censys_id.is_some() && self.censys_secret.is_some())
            || self.criminalip_key.is_some()
    }
}
