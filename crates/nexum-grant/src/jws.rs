//! Compact JWS (RFC 7515) restricted to `alg: EdDSA` / Ed25519 (RFC 8037).
//!
//! Accepting exactly one algorithm removes algorithm-confusion attacks
//! (`alg: none`, HS256-with-public-key, ...) by construction. Signatures are
//! checked with `verify_strict`, which rejects malleable/small-order inputs.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::GrantError;

/// Upper bound on any token we will parse, before doing any work on it.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub alg: String,
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

pub fn sign<T: Serialize>(
    claims: &T,
    typ: &str,
    kid: Option<&str>,
    key: &SigningKey,
) -> Result<String, GrantError> {
    let header = Header {
        alg: "EdDSA".into(),
        typ: typ.into(),
        kid: kid.map(str::to_owned),
    };
    let h = B64.encode(serde_json::to_vec(&header).map_err(|_| GrantError::Malformed)?);
    let p = B64.encode(serde_json::to_vec(claims).map_err(|_| GrantError::Malformed)?);
    let input = format!("{h}.{p}");
    let sig = key.sign(input.as_bytes());
    Ok(format!("{input}.{}", B64.encode(sig.to_bytes())))
}

/// A parsed but **unverified** token. Only `verify` yields trusted claims.
#[derive(Debug)]
pub struct Unverified<'a> {
    pub header: Header,
    signing_input: &'a str,
    payload: Vec<u8>,
    signature: Signature,
}

pub fn parse<'a>(token: &'a str, expected_typ: &str) -> Result<Unverified<'a>, GrantError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(GrantError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(GrantError::Malformed);
    };
    let decode = |x: &str| B64.decode(x).map_err(|_| GrantError::Malformed);
    // deny_unknown_fields rejects `crit`, `jku`, `x5u`, embedded `jwk` etc.
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| GrantError::Malformed)?;
    if header.alg != "EdDSA" {
        return Err(GrantError::UnsupportedAlgorithm);
    }
    if header.typ != expected_typ {
        return Err(GrantError::Malformed);
    }
    let sig_bytes: [u8; 64] = decode(s)?.try_into().map_err(|_| GrantError::Malformed)?;
    Ok(Unverified {
        header,
        signing_input: &token[..h.len() + 1 + p.len()],
        payload: decode(p)?,
        signature: Signature::from_bytes(&sig_bytes),
    })
}

impl Unverified<'_> {
    /// Peek at claims before verification, solely to select the verification
    /// key. Never make an authorization decision from these.
    pub fn peek<T: DeserializeOwned>(&self) -> Result<T, GrantError> {
        serde_json::from_slice(&self.payload).map_err(|_| GrantError::Malformed)
    }

    pub fn verify<T: DeserializeOwned>(&self, key: &VerifyingKey) -> Result<T, GrantError> {
        key.verify_strict(self.signing_input.as_bytes(), &self.signature)
            .map_err(|_| GrantError::InvalidSignature)?;
        self.peek()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn round_trip_and_tamper() {
        let key = SigningKey::generate(&mut OsRng);
        let tok = sign(&serde_json::json!({"a": 1}), "test", Some("k1"), &key).unwrap();
        let v: serde_json::Value = parse(&tok, "test")
            .unwrap()
            .verify(&key.verifying_key())
            .unwrap();
        assert_eq!(v["a"], 1);

        // Wrong key.
        let other = SigningKey::generate(&mut OsRng);
        assert!(matches!(
            parse(&tok, "test")
                .unwrap()
                .verify::<serde_json::Value>(&other.verifying_key()),
            Err(GrantError::InvalidSignature)
        ));

        // Modified payload with original signature.
        let parts: Vec<&str> = tok.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], B64.encode(br#"{"a":2}"#), parts[2]);
        assert!(matches!(
            parse(&forged, "test")
                .unwrap()
                .verify::<serde_json::Value>(&key.verifying_key()),
            Err(GrantError::InvalidSignature)
        ));

        // Wrong typ.
        assert!(parse(&tok, "other").is_err());
    }

    #[test]
    fn rejects_other_algorithms_and_headers() {
        for header in [
            r#"{"alg":"none","typ":"test"}"#,
            r#"{"alg":"HS256","typ":"test"}"#,
            r#"{"alg":"EdDSA","typ":"test","jku":"https://evil"}"#,
            r#"{"alg":"EdDSA","typ":"test","crit":["exp"]}"#,
        ] {
            let tok = format!(
                "{}.{}.{}",
                B64.encode(header),
                B64.encode("{}"),
                B64.encode([0u8; 64])
            );
            assert!(parse(&tok, "test").is_err(), "{header}");
        }
        assert!(parse("a.b", "test").is_err());
        assert!(parse("a.b.c.d", "test").is_err());
        assert!(parse(&"a".repeat(MAX_TOKEN_LEN + 1), "test").is_err());
    }
}
