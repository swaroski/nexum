//! The receiving organization's trust store: which foreign (and local) trust
//! domains it accepts grants from, with which keys, for which capabilities.

use std::collections::BTreeMap;

use nexum_core::{Capability, TrustDomain, set_covers};
use serde::{Deserialize, Serialize};

use crate::keys::Jwk;

pub const DEFAULT_MAX_GRANT_TTL_SECONDS: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDomainConfig {
    /// Expected `iss` of root grants from this domain.
    pub issuer: String,
    /// Static JWKS. Every key must carry a `kid`.
    pub keys: Vec<Jwk>,
    /// Capabilities this domain's agents may exercise here.
    #[serde(default)]
    pub allow: Vec<Capability>,
    /// Capabilities never accepted from this domain, even if allowed above.
    #[serde(default)]
    pub deny: Vec<Capability>,
    #[serde(default = "default_ttl")]
    pub max_grant_ttl_seconds: i64,
}

fn default_ttl() -> i64 {
    DEFAULT_MAX_GRANT_TTL_SECONDS
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    #[serde(rename = "apiVersion", default = "api_version")]
    pub api_version: String,
    #[serde(default)]
    pub trust_domains: BTreeMap<TrustDomain, TrustDomainConfig>,
}

fn api_version() -> String {
    nexum_core::API_VERSION.into()
}

impl TrustStore {
    pub fn validate(&self) -> Result<(), String> {
        if self.api_version != nexum_core::API_VERSION {
            return Err(format!("unsupported apiVersion {:?}", self.api_version));
        }
        for (name, d) in &self.trust_domains {
            if d.keys.is_empty() {
                return Err(format!("trust domain {name}: no keys"));
            }
            for k in &d.keys {
                k.to_key()
                    .map_err(|e| format!("trust domain {name}: bad key: {e}"))?;
                if k.kid.as_deref().is_none_or(str::is_empty) {
                    return Err(format!("trust domain {name}: every key needs a kid"));
                }
            }
            if d.max_grant_ttl_seconds <= 0 {
                return Err(format!(
                    "trust domain {name}: max_grant_ttl_seconds must be > 0"
                ));
            }
        }
        Ok(())
    }

    pub fn domain(&self, name: &TrustDomain) -> Option<&TrustDomainConfig> {
        self.trust_domains.get(name)
    }

    /// Does `domain` accept `action` (allowed and not denied)?
    pub fn accepts(&self, domain: &TrustDomain, action: &Capability) -> bool {
        self.domain(domain)
            .is_some_and(|d| set_covers(&d.allow, action) && !set_covers(&d.deny, action))
    }
}
