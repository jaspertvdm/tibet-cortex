use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::crypto::ContentHash;

/// TIBET provenance token — who did what, when, why
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TibetToken {
    pub token_id: String,
    pub parent_id: Option<String>,
    pub timestamp: DateTime<Utc>,

    // ERIN — what's IN the action
    pub erin: ContentHash,

    // ERAAN — what's attached (dependencies, references)
    pub eraan: Vec<String>,

    // EROMHEEN — context around it
    pub eromheen: Eromheen,

    // ERACHTER — intent behind it
    pub erachter: String,

    // Signature over the token
    pub signature: Option<Vec<u8>>,
}

/// Context surrounding a TIBET action
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Eromheen {
    pub actor: String,
    pub jis_level: u8,
    pub chunks_accessed: usize,
    pub chunks_denied: usize,
    pub airlock_session_ms: Option<f64>,
}

/// Full provenance chain — append-only audit trail
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provenance {
    pub chain: Vec<TibetToken>,
}

impl TibetToken {
    pub fn new(
        erin: ContentHash,
        erachter: impl Into<String>,
        actor: impl Into<String>,
        jis_level: u8,
    ) -> Self {
        let id = format!("tibet_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
        Self {
            token_id: id,
            parent_id: None,
            timestamp: Utc::now(),
            erin,
            eraan: Vec::new(),
            eromheen: Eromheen {
                actor: actor.into(),
                jis_level,
                chunks_accessed: 0,
                chunks_denied: 0,
                airlock_session_ms: None,
            },
            erachter: erachter.into(),
            signature: None,
        }
    }

    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    pub fn with_access_stats(mut self, accessed: usize, denied: usize) -> Self {
        self.eromheen.chunks_accessed = accessed;
        self.eromheen.chunks_denied = denied;
        self
    }

    pub fn with_airlock_time(mut self, ms: f64) -> Self {
        self.eromheen.airlock_session_ms = Some(ms);
        self
    }

    /// Serialize the signable portion (everything except signature)
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut token = self.clone();
        token.signature = None;
        serde_json::to_vec(&token).unwrap_or_default()
    }
}

impl Provenance {
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }

    pub fn append(&mut self, token: TibetToken) {
        self.chain.push(token);
    }

    pub fn latest(&self) -> Option<&TibetToken> {
        self.chain.last()
    }

    pub fn len(&self) -> usize {
        self.chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Verify the chain is unbroken: each token's parent_id matches the previous token_id
    pub fn verify_chain(&self) -> bool {
        for window in self.chain.windows(2) {
            let parent = &window[0];
            let child = &window[1];
            match &child.parent_id {
                Some(pid) if pid == &parent.token_id => continue,
                _ => return false,
            }
        }
        true
    }
}

impl Default for Provenance {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation() {
        let hash = ContentHash("sha256:abc123".into());
        let token = TibetToken::new(hash, "test query", "user@test.com", 2);
        assert!(token.token_id.starts_with("tibet_"));
        assert_eq!(token.eromheen.jis_level, 2);
        assert_eq!(token.erachter, "test query");
    }

    #[test]
    fn test_provenance_chain() {
        let h1 = ContentHash("sha256:aaa".into());
        let h2 = ContentHash("sha256:bbb".into());

        let t1 = TibetToken::new(h1, "first", "actor", 0);
        let t1_id = t1.token_id.clone();
        let t2 = TibetToken::new(h2, "second", "actor", 0).with_parent(t1_id);

        let mut prov = Provenance::new();
        prov.append(t1);
        prov.append(t2);

        assert_eq!(prov.len(), 2);
        assert!(prov.verify_chain());
    }

    #[test]
    fn test_broken_chain() {
        let h1 = ContentHash("sha256:aaa".into());
        let h2 = ContentHash("sha256:bbb".into());

        let t1 = TibetToken::new(h1, "first", "actor", 0);
        let t2 = TibetToken::new(h2, "second", "actor", 0).with_parent("wrong_parent");

        let mut prov = Provenance::new();
        prov.append(t1);
        prov.append(t2);

        assert!(!prov.verify_chain());
    }
}
