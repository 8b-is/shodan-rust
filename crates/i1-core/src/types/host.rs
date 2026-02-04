use super::{GeoLocation, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Complete host information from Shodan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// IP address (parsed) - skipped during deserialization as Shodan returns integer
    #[serde(skip_deserializing, default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,

    /// IP address as string
    pub ip_str: String,

    /// Hostnames associated with this IP
    #[serde(default)]
    pub hostnames: Vec<String>,

    /// Domains associated with this IP
    #[serde(default)]
    pub domains: Vec<String>,

    /// Organization that owns the IP
    #[serde(default)]
    pub org: Option<String>,

    /// Autonomous System Number
    #[serde(default)]
    pub asn: Option<String>,

    /// Internet Service Provider
    #[serde(default)]
    pub isp: Option<String>,

    /// Operating system (if detected)
    #[serde(default)]
    pub os: Option<String>,

    /// Open ports detected
    #[serde(default)]
    pub ports: Vec<u16>,

    /// Known vulnerabilities (CVE IDs)
    #[serde(default)]
    pub vulns: Vec<String>,

    /// Tags assigned to this host
    #[serde(default)]
    pub tags: Vec<String>,

    /// Geographic location
    #[serde(flatten, default)]
    pub location: GeoLocation,

    /// Services/banners found on this host
    #[serde(default)]
    pub data: Vec<Service>,

    /// Last time the host was scanned
    #[serde(default)]
    pub last_update: Option<String>,
}

impl HostInfo {
    /// Returns the IP address, parsing from string if needed
    #[must_use]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip.or_else(|| self.ip_str.parse().ok())
    }

    /// Returns true if the host has known vulnerabilities
    #[must_use]
    pub fn is_vulnerable(&self) -> bool {
        !self.vulns.is_empty()
    }

    /// Returns the number of open services
    #[must_use]
    pub fn service_count(&self) -> usize {
        self.data.len()
    }
}

/// Individual service/banner information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Port number
    pub port: u16,

    /// Transport protocol
    #[serde(default)]
    pub transport: Transport,

    /// Product name (e.g., "Apache", "nginx")
    #[serde(default)]
    pub product: Option<String>,

    /// Product version
    #[serde(default)]
    pub version: Option<String>,

    /// Common Platform Enumeration identifiers
    #[serde(default)]
    pub cpe: Vec<String>,

    /// Raw banner data
    #[serde(default)]
    pub data: Option<String>,

    /// Timestamp of when this banner was collected
    #[serde(default)]
    pub timestamp: Option<String>,

    /// Module that collected this banner
    #[serde(default, rename = "_shodan")]
    pub shodan_module: Option<ShodanModule>,

    /// HTTP-specific data
    #[serde(default)]
    pub http: Option<HttpData>,

    /// SSL/TLS-specific data
    #[serde(default)]
    pub ssl: Option<SslData>,

    /// SSH-specific data
    #[serde(default)]
    pub ssh: Option<SshData>,

    /// Vulnerabilities affecting this service
    #[serde(default)]
    pub vulns: HashMap<String, VulnInfo>,

    /// Additional tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// Device type
    #[serde(default)]
    pub devicetype: Option<String>,

    /// Information about the service (from module)
    #[serde(default)]
    pub info: Option<String>,

    /// Operating system
    #[serde(default)]
    pub os: Option<String>,
}

/// Shodan crawler module information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanModule {
    /// Crawler that collected the data
    #[serde(default)]
    pub crawler: Option<String>,

    /// Module name
    #[serde(default)]
    pub module: Option<String>,

    /// Unique ID for this result
    #[serde(default)]
    pub id: Option<String>,

    /// Options used during scan
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
}

/// HTTP-specific service data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpData {
    /// HTTP status code
    #[serde(default)]
    pub status: Option<u16>,

    /// Page title
    #[serde(default)]
    pub title: Option<String>,

    /// Server header value
    #[serde(default)]
    pub server: Option<String>,

    /// Host header
    #[serde(default)]
    pub host: Option<String>,

    /// HTML content (truncated)
    #[serde(default)]
    pub html: Option<String>,

    /// robots.txt content
    #[serde(default)]
    pub robots: Option<String>,

    /// Sitemap content
    #[serde(default)]
    pub sitemap: Option<String>,

    /// Security headers
    #[serde(default, rename = "securitytxt")]
    pub security_txt: Option<String>,

    /// HTTP headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Redirect location
    #[serde(default)]
    pub location: Option<String>,

    /// Hash of the favicon
    #[serde(default)]
    pub favicon: Option<FaviconInfo>,

    /// HTTP components detected
    #[serde(default)]
    pub components: HashMap<String, ComponentInfo>,
}

/// Favicon information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaviconInfo {
    /// Hash of the favicon
    #[serde(default)]
    pub hash: Option<i64>,

    /// URL of the favicon
    #[serde(default)]
    pub url: Option<String>,
}

/// HTTP component information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// Categories this component belongs to
    #[serde(default)]
    pub categories: Vec<String>,
}

/// SSL/TLS certificate and connection data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslData {
    /// Certificate information
    #[serde(default)]
    pub cert: Option<Certificate>,

    /// Cipher suite in use
    #[serde(default)]
    pub cipher: Option<CipherSuite>,

    /// Certificate chain
    #[serde(default)]
    pub chain: Vec<String>,

    /// TLS versions supported
    #[serde(default)]
    pub versions: Vec<String>,

    /// ALPN protocols
    #[serde(default)]
    pub alpn: Vec<String>,

    /// TLS extensions
    #[serde(default)]
    pub tlsext: Vec<TlsExtension>,

    /// Whether the certificate is trusted
    #[serde(default)]
    pub acceptable_cas: Vec<String>,

    /// OCSP stapling response
    #[serde(default)]
    pub ocsp: HashMap<String, serde_json::Value>,

    /// JARM fingerprint
    #[serde(default)]
    pub jarm: Option<String>,

    /// JA3S fingerprint
    #[serde(default)]
    pub ja3s: Option<String>,
}

/// X.509 certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Whether the certificate is expired
    #[serde(default)]
    pub expired: bool,

    /// Certificate version
    #[serde(default)]
    pub version: Option<i32>,

    /// Serial number
    #[serde(default)]
    pub serial: Option<serde_json::Value>,

    /// Signature algorithm
    #[serde(default)]
    pub sig_alg: Option<String>,

    /// Issuer information
    #[serde(default)]
    pub issuer: HashMap<String, String>,

    /// Subject information
    #[serde(default)]
    pub subject: HashMap<String, String>,

    /// Subject Alternative Names
    #[serde(default)]
    pub subject_alt_names: Vec<String>,

    /// Certificate fingerprint (SHA256)
    #[serde(default)]
    pub fingerprint: HashMap<String, String>,

    /// Public key information
    #[serde(default)]
    pub pubkey: Option<PublicKeyInfo>,

    /// Validity period
    #[serde(default)]
    pub validity: Option<CertValidity>,

    /// Certificate extensions
    #[serde(default)]
    pub extensions: Vec<CertExtension>,
}

/// Certificate validity period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertValidity {
    /// Valid from date
    #[serde(default, rename = "start")]
    pub not_before: Option<String>,

    /// Valid until date
    #[serde(default, rename = "end")]
    pub not_after: Option<String>,
}

/// Public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Key type (RSA, EC, etc.)
    #[serde(default, rename = "type")]
    pub key_type: Option<String>,

    /// Key size in bits
    #[serde(default)]
    pub bits: Option<u32>,
}

/// Certificate extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertExtension {
    /// Extension name
    #[serde(default)]
    pub name: Option<String>,

    /// Whether it's critical
    #[serde(default)]
    pub critical: bool,

    /// Extension data
    #[serde(default)]
    pub data: Option<String>,
}

/// Cipher suite information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuite {
    /// Cipher suite name
    #[serde(default)]
    pub name: Option<String>,

    /// Cipher version
    #[serde(default)]
    pub version: Option<String>,

    /// Key bits
    #[serde(default)]
    pub bits: Option<u32>,
}

/// TLS extension information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    /// Extension ID
    #[serde(default)]
    pub id: Option<u16>,

    /// Extension name
    #[serde(default)]
    pub name: Option<String>,
}

/// SSH-specific service data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshData {
    /// SSH type (e.g., "ssh-rsa")
    #[serde(default, rename = "type")]
    pub key_type: Option<String>,

    /// SSH key fingerprint
    #[serde(default)]
    pub fingerprint: Option<String>,

    /// MAC algorithms
    #[serde(default)]
    pub mac: Option<String>,

    /// Cipher algorithms
    #[serde(default)]
    pub cipher: Option<String>,

    /// Key exchange algorithm
    #[serde(default)]
    pub kex: Option<SshKeyExchange>,

    /// SSH key
    #[serde(default)]
    pub key: Option<String>,

    /// HASSH fingerprint
    #[serde(default)]
    pub hassh: Option<String>,
}

/// SSH key exchange information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyExchange {
    /// Key exchange algorithms
    #[serde(default)]
    pub kex_algorithms: Vec<String>,

    /// Server host key algorithms
    #[serde(default)]
    pub server_host_key_algorithms: Vec<String>,

    /// Encryption algorithms (client to server)
    #[serde(default)]
    pub encryption_algorithms: Vec<String>,

    /// MAC algorithms
    #[serde(default)]
    pub mac_algorithms: Vec<String>,

    /// Compression algorithms
    #[serde(default)]
    pub compression_algorithms: Vec<String>,
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    /// CVE ID
    #[serde(default)]
    pub cve: Option<String>,

    /// Whether the vulnerability is verified
    #[serde(default)]
    pub verified: bool,

    /// CVSS score
    #[serde(default)]
    pub cvss: Option<f64>,

    /// Summary of the vulnerability
    #[serde(default)]
    pub summary: Option<String>,

    /// References
    #[serde(default)]
    pub references: Vec<String>,
}
