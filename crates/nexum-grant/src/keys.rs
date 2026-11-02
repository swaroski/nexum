//! Ed25519 keys and their JWK (RFC 8037 `OKP`) representation.
//!
//! Local key files are for development. Production deployments should keep
//! signing keys in a KMS/HSM; see `ARCHITECTURE.md` ("Key custody").

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::GrantError;

/// Public Ed25519 key as a JWK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    pub fn from_key(key: &VerifyingKey, kid: Option<String>) -> Self {
        Self {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: B64.encode(key.as_bytes()),
            kid,
            alg: Some("EdDSA".into()),
            use_: None,
        }
    }

    pub fn to_key(&self) -> Result<VerifyingKey, GrantError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(GrantError::UnsupportedAlgorithm);
        }
        if self.alg.as_deref().is_some_and(|a| a != "EdDSA") {
            return Err(GrantError::UnsupportedAlgorithm);
        }
        let bytes: [u8; 32] = B64
            .decode(&self.x)
            .map_err(|_| GrantError::Malformed)?
            .try_into()
            .map_err(|_| GrantError::Malformed)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| GrantError::Malformed)?;
        if key.is_weak() {
            return Err(GrantError::Malformed);
        }
        Ok(key)
    }

    /// RFC 7638 JWK thumbprint (base64url SHA-256), used as a stable key id.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
            self.crv, self.kty, self.x
        );
        B64.encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// A private signing key plus its key id. Serialized as a private JWK (`d`).
#[derive(Clone)]
pub struct KeyPair {
    pub kid: String,
    pub signing: SigningKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateJwk {
    kty: String,
    crv: String,
    x: String,
    d: String,
    kid: String,
    alg: String,
}

impl KeyPair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let kid = Jwk::from_key(&signing.verifying_key(), None).thumbprint();
        Self { kid, signing }
    }

    pub fn public_jwk(&self) -> Jwk {
        Jwk::from_key(&self.signing.verifying_key(), Some(self.kid.clone()))
    }

    pub fn to_json(&self) -> String {
        let p = PrivateJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: B64.encode(self.signing.verifying_key().as_bytes()),
            d: B64.encode(self.signing.to_bytes()),
            kid: self.kid.clone(),
            alg: "EdDSA".into(),
        };
        serde_json::to_string_pretty(&p).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Result<Self, GrantError> {
        let p: PrivateJwk = serde_json::from_str(s).map_err(|_| GrantError::Malformed)?;
        if p.kty != "OKP" || p.crv != "Ed25519" || p.alg != "EdDSA" {
            return Err(GrantError::UnsupportedAlgorithm);
        }
        let d: [u8; 32] = B64
            .decode(&p.d)
            .map_err(|_| GrantError::Malformed)?
            .try_into()
            .map_err(|_| GrantError::Malformed)?;
        let signing = SigningKey::from_bytes(&d);
        // Refuse files whose public half does not match the private half.
        if B64.encode(signing.verifying_key().as_bytes()) != p.x {
            return Err(GrantError::Malformed);
        }
        Ok(Self {
            kid: p.kid,
            signing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_round_trip() {
        let k = KeyPair::generate();
        let back = KeyPair::from_json(&k.to_json()).unwrap();
        assert_eq!(back.kid, k.kid);
        assert_eq!(
            back.public_jwk().to_key().unwrap(),
            k.signing.verifying_key()
        );
    }

    #[test]
    fn rejects_mismatched_key_file() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let mut v: serde_json::Value = serde_json::from_str(&a.to_json()).unwrap();
        v["x"] = b.public_jwk().x.into();
        assert!(KeyPair::from_json(&v.to_string()).is_err());
    }

    #[test]
    fn rejects_non_ed25519_jwk() {
        let mut jwk = KeyPair::generate().public_jwk();
        jwk.crv = "P-256".into();
        assert!(jwk.to_key().is_err());
    }
}
