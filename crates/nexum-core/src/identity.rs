//! Agent identities.
//!
//! Nexum uses SPIFFE IDs (`spiffe://<trust-domain>/<path>`) as the canonical
//! agent identifier. Parsing follows the SPIFFE-ID specification: lowercase
//! trust domain, no empty / `.` / `..` path segments, no query, fragment,
//! port or userinfo, and a 2048-byte length cap.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Error;

const MAX_ID_LEN: usize = 2048;
const MAX_TRUST_DOMAIN_LEN: usize = 255;

/// A SPIFFE trust domain, e.g. `xyz.com`. One trust domain == one organization
/// root of trust.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TrustDomain(String);

impl TrustDomain {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let valid = !s.is_empty()
            && s.len() <= MAX_TRUST_DOMAIN_LEN
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
        if !valid {
            return Err(Error::InvalidTrustDomain(s.to_owned()));
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TrustDomain {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::parse(&s)
    }
}

impl From<TrustDomain> for String {
    fn from(t: TrustDomain) -> String {
        t.0
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated SPIFFE ID identifying an agent (or any workload).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentId {
    raw: String,
    domain_end: usize,
}

impl AgentId {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let err = || Error::InvalidAgentId(s.to_owned());
        if s.len() > MAX_ID_LEN {
            return Err(err());
        }
        let rest = s.strip_prefix("spiffe://").ok_or_else(err)?;
        let (domain, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        TrustDomain::parse(domain).map_err(|_| err())?;
        if !path.is_empty() {
            for seg in path[1..].split('/') {
                let ok = !seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
                if !ok {
                    return Err(err());
                }
            }
        }
        Ok(Self {
            raw: s.to_owned(),
            domain_end: "spiffe://".len() + domain.len(),
        })
    }

    pub fn trust_domain(&self) -> TrustDomain {
        TrustDomain(self.raw["spiffe://".len()..self.domain_end].to_owned())
    }

    pub fn path(&self) -> &str {
        &self.raw[self.domain_end..]
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl FromStr for AgentId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for AgentId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::parse(&s)
    }
}

impl From<AgentId> for String {
    fn from(a: AgentId) -> String {
        a.raw
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ids() {
        let id = AgentId::parse("spiffe://xyz.com/agents/procurement/prod").unwrap();
        assert_eq!(id.trust_domain().as_str(), "xyz.com");
        assert_eq!(id.path(), "/agents/procurement/prod");
        assert!(AgentId::parse("spiffe://xyz.com").is_ok());
    }

    #[test]
    fn rejects_invalid_ids() {
        for bad in [
            "https://xyz.com/agent",
            "spiffe://",
            "spiffe://XYZ.com/a",
            "spiffe://xyz.com/",
            "spiffe://xyz.com//a",
            "spiffe://xyz.com/a/../b",
            "spiffe://xyz.com/./b",
            "spiffe://xyz.com:443/a",
            "spiffe://user@xyz.com/a",
            "spiffe://xyz.com/a?x=1",
            "spiffe://xyz.com/a#f",
            "spiffe://xyz.com/a%2Fb",
        ] {
            assert!(AgentId::parse(bad).is_err(), "{bad} should be rejected");
        }
        assert!(AgentId::parse(&format!("spiffe://x.com/{}", "a".repeat(2048))).is_err());
    }

    #[test]
    fn serde_round_trip_validates() {
        let id: AgentId = serde_json::from_str("\"spiffe://abc.com/agents/supplier\"").unwrap();
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            "\"spiffe://abc.com/agents/supplier\""
        );
        assert!(serde_json::from_str::<AgentId>("\"spiffe://abc.com/../x\"").is_err());
    }
}
