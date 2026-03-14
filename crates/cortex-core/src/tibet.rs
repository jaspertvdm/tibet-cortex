use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::crypto::{ContentHash, KeyPair};
use crate::error::{CortexError, CortexResult};

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

    /// Sign this token with an Ed25519 keypair.
    /// Sets the signature field in-place and returns a reference to self.
    pub fn sign(mut self, keypair: &KeyPair) -> Self {
        let bytes = self.signable_bytes();
        self.signature = Some(keypair.sign(&bytes));
        self
    }

    /// Verify this token's Ed25519 signature against a public key.
    /// Returns Ok(()) if valid, Err if missing or invalid.
    pub fn verify_signature(&self, keypair: &KeyPair) -> CortexResult<()> {
        match &self.signature {
            Some(sig) => keypair.verify(&self.signable_bytes(), sig),
            None => Err(CortexError::SignatureInvalid),
        }
    }

    /// Check if this token is signed
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
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

    /// Verify both chain integrity AND all token signatures.
    /// Every token in the chain must be signed and valid.
    pub fn verify_signatures(&self, keypair: &KeyPair) -> bool {
        if !self.verify_chain() {
            return false;
        }
        self.chain.iter().all(|t| t.verify_signature(keypair).is_ok())
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

    #[test]
    fn test_token_sign_verify() {
        let kp = KeyPair::generate();
        let hash = ContentHash::compute(b"test data");
        let token = TibetToken::new(hash, "signed action", "actor@test", 2).sign(&kp);

        assert!(token.is_signed());
        assert!(token.verify_signature(&kp).is_ok());
    }

    #[test]
    fn test_unsigned_token_fails_verify() {
        let kp = KeyPair::generate();
        let hash = ContentHash::compute(b"test");
        let token = TibetToken::new(hash, "unsigned", "actor", 0);

        assert!(!token.is_signed());
        assert!(token.verify_signature(&kp).is_err());
    }

    #[test]
    fn test_wrong_key_fails_verify() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let hash = ContentHash::compute(b"data");
        let token = TibetToken::new(hash, "action", "actor", 0).sign(&kp1);

        assert!(token.verify_signature(&kp2).is_err());
    }

    #[test]
    fn test_signed_chain_verify() {
        let kp = KeyPair::generate();
        let h1 = ContentHash::compute(b"first");
        let h2 = ContentHash::compute(b"second");
        let h3 = ContentHash::compute(b"third");

        let t1 = TibetToken::new(h1, "first", "actor", 0).sign(&kp);
        let t1_id = t1.token_id.clone();
        let t2 = TibetToken::new(h2, "second", "actor", 0)
            .with_parent(&t1_id)
            .sign(&kp);
        let t2_id = t2.token_id.clone();
        let t3 = TibetToken::new(h3, "third", "actor", 0)
            .with_parent(&t2_id)
            .sign(&kp);

        let mut prov = Provenance::new();
        prov.append(t1);
        prov.append(t2);
        prov.append(t3);

        assert!(prov.verify_chain());
        assert!(prov.verify_signatures(&kp));
    }

    #[test]
    fn test_mixed_signed_unsigned_chain_fails() {
        let kp = KeyPair::generate();
        let h1 = ContentHash::compute(b"first");
        let h2 = ContentHash::compute(b"second");

        let t1 = TibetToken::new(h1, "first", "actor", 0).sign(&kp);
        let t1_id = t1.token_id.clone();
        // t2 unsigned — should fail verify_signatures
        let t2 = TibetToken::new(h2, "second", "actor", 0).with_parent(&t1_id);

        let mut prov = Provenance::new();
        prov.append(t1);
        prov.append(t2);

        assert!(prov.verify_chain()); // chain structure OK
        assert!(!prov.verify_signatures(&kp)); // but signatures fail
    }
}
