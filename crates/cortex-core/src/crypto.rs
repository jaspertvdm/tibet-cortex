use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CortexError, CortexResult};

/// Ed25519 keypair with zeroize-on-drop for the signing key
pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing.sign(data).to_bytes().to_vec()
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> CortexResult<()> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| CortexError::Crypto(e.to_string()))?;
        self.verifying
            .verify(data, &sig)
            .map_err(|_| CortexError::SignatureInvalid)
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(bytes);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // SigningKey implements Zeroize internally in ed25519-dalek
    }
}

/// SHA-256 content hash with display and comparison
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub String);

impl ContentHash {
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self(format!("sha256:{}", hex::encode(result)))
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Self::compute(data);
        computed == *self
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Zeroizing byte buffer — wipes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sign_verify() {
        let kp = KeyPair::generate();
        let data = b"TIBET Cortex test data";
        let sig = kp.sign(data);
        assert!(kp.verify(data, &sig).is_ok());
    }

    #[test]
    fn test_tampered_data_fails() {
        let kp = KeyPair::generate();
        let data = b"original data";
        let sig = kp.sign(data);
        assert!(kp.verify(b"tampered data", &sig).is_err());
    }

    #[test]
    fn test_content_hash() {
        let data = b"hello cortex";
        let hash = ContentHash::compute(data);
        assert!(hash.verify(data));
        assert!(!hash.verify(b"tampered"));
        assert!(hash.as_str().starts_with("sha256:"));
    }

    #[test]
    fn test_secure_buffer_basics() {
        let buf = SecureBuffer::new(vec![1, 2, 3, 4]);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.as_bytes(), &[1, 2, 3, 4]);
        assert!(!buf.is_empty());
        // On drop, data is zeroized
    }
}
