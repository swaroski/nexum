//! Capabilities (what may be done) and resource patterns (to what).
//!
//! Both are patterns with an optional trailing wildcard. The single operation
//! that matters for security is `covers`: "does holding `self` imply holding
//! `other`?". Delegation attenuation is defined entirely in terms of it:
//! a child set is valid iff every child pattern is covered by some parent
//! pattern.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Error;

const MAX_PATTERN_LEN: usize = 512;

/// A dot-separated capability such as `inventory.read`, or a pattern such as
/// `inventory.*` (all capabilities strictly below `inventory`) or `*` (all).
///
/// Segments are `[A-Za-z0-9_-]+` and case-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Capability(String);

impl Capability {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let err = || Error::InvalidCapability(s.to_owned());
        if s.is_empty() || s.len() > MAX_PATTERN_LEN {
            return Err(err());
        }
        let segs: Vec<&str> = s.split('.').collect();
        for (i, seg) in segs.iter().enumerate() {
            let is_last = i == segs.len() - 1;
            let ok = (is_last && *seg == "*")
                || (!seg.is_empty()
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
            if !ok {
                return Err(err());
            }
        }
        Ok(Self(s.to_owned()))
    }

    /// True if this is a concrete action (no wildcard).
    pub fn is_exact(&self) -> bool {
        !self.0.ends_with('*')
    }

    fn base(&self) -> Vec<&str> {
        let mut segs: Vec<&str> = self.0.split('.').collect();
        if !self.is_exact() {
            segs.pop();
        }
        segs
    }

    /// Does holding `self` imply holding `other`?
    pub fn covers(&self, other: &Capability) -> bool {
        if self.is_exact() {
            return self == other;
        }
        let (mine, theirs) = (self.base(), other.base());
        theirs.starts_with(&mine) && (theirs.len() > mine.len() || !other.is_exact())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Capability {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::parse(&s)
    }
}

impl From<Capability> for String {
    fn from(c: Capability) -> String {
        c.0
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A resource URI such as `supplier://abc/sku/123`, or a prefix pattern
/// ending in `*` such as `supplier://abc/sku/*`.
///
/// Prefix matching is literal: `supplier://abc*` also matches
/// `supplier://abcevil/...`. End prefixes with `/` to avoid that.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ResourcePattern(String);

impl ResourcePattern {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let body = s.strip_suffix('*').unwrap_or(s);
        let ok = !s.is_empty()
            && s.len() <= MAX_PATTERN_LEN
            && !body.contains('*')
            && !s.chars().any(|c| c.is_whitespace() || c.is_control());
        if !ok {
            return Err(Error::InvalidResource(s.to_owned()));
        }
        Ok(Self(s.to_owned()))
    }

    pub fn is_exact(&self) -> bool {
        !self.0.ends_with('*')
    }

    fn base(&self) -> &str {
        self.0.strip_suffix('*').unwrap_or(&self.0)
    }

    pub fn covers(&self, other: &ResourcePattern) -> bool {
        if self.is_exact() {
            return self == other;
        }
        other.base().starts_with(self.base())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ResourcePattern {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        Self::parse(&s)
    }
}

impl From<ResourcePattern> for String {
    fn from(r: ResourcePattern) -> String {
        r.0
    }
}

impl fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Is `item` covered by at least one capability in `set`?
pub fn set_covers(set: &[Capability], item: &Capability) -> bool {
    set.iter().any(|p| p.covers(item))
}

/// `child ⊆ parent` under `covers`.
pub fn is_attenuation(child: &[Capability], parent: &[Capability]) -> bool {
    child.iter().all(|c| set_covers(parent, c))
}

pub fn resources_cover(set: &[ResourcePattern], item: &ResourcePattern) -> bool {
    set.iter().any(|p| p.covers(item))
}

pub fn is_resource_attenuation(child: &[ResourcePattern], parent: &[ResourcePattern]) -> bool {
    child.iter().all(|c| resources_cover(parent, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cap(s: &str) -> Capability {
        Capability::parse(s).unwrap()
    }

    #[test]
    fn wildcard_semantics() {
        assert!(cap("inventory.*").covers(&cap("inventory.read")));
        assert!(cap("inventory.*").covers(&cap("inventory.read.bulk")));
        assert!(cap("inventory.*").covers(&cap("inventory.sku.*")));
        assert!(cap("inventory.*").covers(&cap("inventory.*")));
        assert!(!cap("inventory.*").covers(&cap("inventory")));
        assert!(!cap("inventory.*").covers(&cap("inventoryx.read")));
        assert!(!cap("inventory.read").covers(&cap("inventory.*")));
        assert!(!cap("inventory.sku.*").covers(&cap("inventory.*")));
        assert!(cap("*").covers(&cap("payment.execute")));
        assert!(!cap("Payment.execute").covers(&cap("payment.execute")));
    }

    #[test]
    fn rejects_bad_capabilities() {
        for bad in ["", ".", "a..b", "a.*.b", "a*", "a.b c", "*.a", "a/b"] {
            assert!(Capability::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resource_prefixes() {
        let p = ResourcePattern::parse("supplier://abc/*").unwrap();
        assert!(p.covers(&ResourcePattern::parse("supplier://abc/sku/1").unwrap()));
        assert!(p.covers(&ResourcePattern::parse("supplier://abc/sku/*").unwrap()));
        assert!(!p.covers(&ResourcePattern::parse("supplier://abd/sku/1").unwrap()));
        let exact = ResourcePattern::parse("supplier://abc/sku/1").unwrap();
        assert!(!exact.covers(&p));
        assert!(ResourcePattern::parse("a*b").is_err());
        assert!(ResourcePattern::parse("a b").is_err());
    }

    fn arb_cap() -> impl Strategy<Value = Capability> {
        (
            prop::collection::vec(prop::sample::select(vec!["a", "b", "c"]), 0..4),
            any::<bool>(),
        )
            .prop_filter_map("non-empty", |(segs, wild)| {
                let mut s = segs.join(".");
                if wild {
                    s = if s.is_empty() {
                        "*".into()
                    } else {
                        format!("{s}.*")
                    };
                }
                Capability::parse(&s).ok()
            })
    }

    proptest! {
        // If parent covers child and child covers an action, parent covers it:
        // authority can never grow through a valid attenuation step.
        #[test]
        fn covers_is_transitive(a in arb_cap(), b in arb_cap(), c in arb_cap()) {
            if a.covers(&b) && b.covers(&c) {
                prop_assert!(a.covers(&c));
            }
        }

        #[test]
        fn attenuated_child_never_exceeds_parent(
            parent in prop::collection::vec(arb_cap(), 0..4),
            child in prop::collection::vec(arb_cap(), 0..4),
            action in arb_cap(),
        ) {
            if is_attenuation(&child, &parent) && set_covers(&child, &action) {
                prop_assert!(set_covers(&parent, &action));
            }
        }

        // Removing capabilities from a set (adding a restriction) never
        // increases what it covers.
        #[test]
        fn restriction_never_increases_authority(
            set in prop::collection::vec(arb_cap(), 1..5),
            drop in any::<prop::sample::Index>(),
            action in arb_cap(),
        ) {
            let mut restricted = set.clone();
            restricted.remove(drop.index(set.len()));
            if set_covers(&restricted, &action) {
                prop_assert!(set_covers(&set, &action));
            }
        }
    }
}
