//! End-entity certificates for TLS.
//!
//! These are the actual certificates used by the proxy.
//! Short-lived, generated on-demand.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CertificateInfo, CertificateType};

/// A signed end-entity certificate with its key.
#[derive(Debug, Clone)]
pub struct EndEntityCert {
    /// PEM-encoded certificate
    pub cert_pem: String,
    /// PEM-encoded private key
    pub key_pem: String,
    /// Full chain (cert + intermediate + root)
    pub chain_pem: String,
    /// Metadata
    pub info: CertificateInfo,
}

/// Request for a new certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// Domain name(s) for the certificate
    pub domains: Vec<String>,
    /// Validity in days (default: 1)
    pub validity_days: u32,
    /// Include wildcard?
    pub include_wildcard: bool,
}

impl Default for CertificateRequest {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            validity_days: 1, // Short-lived by default
            include_wildcard: false,
        }
    }
}

impl CertificateRequest {
    /// Create a request for a single domain.
    pub fn for_domain(domain: impl Into<String>) -> Self {
        Self {
            domains: vec![domain.into()],
            validity_days: 1,
            include_wildcard: false,
        }
    }

    /// Create a request for a domain with wildcard.
    pub fn for_domain_with_wildcard(domain: impl Into<String>) -> Self {
        let d = domain.into();
        Self {
            domains: vec![d.clone(), format!("*.{}", d)],
            validity_days: 1,
            include_wildcard: true,
        }
    }

    /// Set validity period.
    pub fn validity(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Add additional domain.
    pub fn add_domain(mut self, domain: impl Into<String>) -> Self {
        self.domains.push(domain.into());
        self
    }
}

impl EndEntityCert {
    /// Create cert info for tracking.
    #[allow(dead_code)] // Future use when IntermediateCa returns EndEntityCert
    pub(crate) fn create_info(
        domains: &[String],
        issuer: &str,
        validity_days: u32,
    ) -> CertificateInfo {
        let now = Utc::now();
        let subject = domains.first().cloned().unwrap_or_default();

        CertificateInfo {
            id: Uuid::new_v4(),
            serial: format!("{:032x}", Uuid::new_v4().as_u128()),
            subject,
            issuer: issuer.to_string(),
            not_before: now,
            not_after: now + Duration::days(validity_days as i64),
            cert_type: CertificateType::EndEntity,
            revoked: false,
            revocation_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_request() {
        let req = CertificateRequest::for_domain("example.com")
            .validity(7)
            .add_domain("www.example.com");

        assert_eq!(req.domains.len(), 2);
        assert_eq!(req.validity_days, 7);
    }

    #[test]
    fn test_wildcard_request() {
        let req = CertificateRequest::for_domain_with_wildcard("example.com");

        assert!(req.domains.contains(&"example.com".to_string()));
        assert!(req.domains.contains(&"*.example.com".to_string()));
    }
}
