//! TIBET Cortex Store — JIS-gated vector storage
//!
//! Stores document chunks as TBZ envelopes in sled:
//! - Embeddings at JIS 0 (always searchable)
//! - Content at JIS N (gated by policy)
//! - Every operation goes through the Airlock

use cortex_core::envelope::{Envelope, EnvelopeBlock};
use cortex_core::crypto::ContentHash;
use cortex_core::error::{CortexError, CortexResult};
use cortex_jis::{JisClaim, JisPolicy, JisGate};
use cortex_airlock::{Airlock, AirlockConfig, AirlockSession};
use serde::{Serialize, Deserialize};

/// A stored document chunk with its JIS policy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredChunk {
    pub envelope: Envelope,
    pub policy: JisPolicy,
}

/// The Cortex Store — sled-backed JIS-gated vector storage
pub struct CortexStore {
    db: sled::Db,
    airlock: Airlock,
}

/// Query result with JIS filtering applied
#[derive(Debug)]
pub struct QueryResult {
    pub chunks: Vec<AccessedChunk>,
    pub total_matched: usize,
    pub total_denied: usize,
    pub session: AirlockSession,
}

#[derive(Debug)]
pub struct AccessedChunk {
    pub id: String,
    pub content: Vec<u8>,
    pub content_hash: ContentHash,
    pub jis_level: u8,
}

impl CortexStore {
    /// Open or create a Cortex Store at the given path
    pub fn open(path: &str) -> CortexResult<Self> {
        let db = sled::open(path)
            .map_err(|e| CortexError::Storage(e.to_string()))?;
        Ok(Self {
            db,
            airlock: Airlock::with_defaults(),
        })
    }

    /// Open with custom airlock config
    pub fn open_with_config(path: &str, config: AirlockConfig) -> CortexResult<Self> {
        let db = sled::open(path)
            .map_err(|e| CortexError::Storage(e.to_string()))?;
        Ok(Self {
            db,
            airlock: Airlock::new(config),
        })
    }

    /// Ingest a document chunk: wrap in envelope, store with policy
    pub fn ingest(
        &self,
        id: &str,
        embedding: Vec<u8>,
        content: Vec<u8>,
        jis_level: u8,
        source: Option<&str>,
    ) -> CortexResult<ContentHash> {
        let mut envelope = Envelope::new(id);
        if let Some(src) = source {
            envelope = envelope.with_source(src);
        }

        // Embedding at JIS 0 — always searchable
        envelope.add_block(EnvelopeBlock::new_embedding(embedding));

        // Content at JIS N — gated
        let content_hash = ContentHash::compute(&content);
        envelope.add_block(EnvelopeBlock::new_content(content, jis_level));

        let stored = StoredChunk {
            envelope,
            policy: JisPolicy::clearance(jis_level),
        };

        let bytes = serde_json::to_vec(&stored)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        self.db
            .insert(id.as_bytes(), bytes)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        tracing::info!(id = id, jis_level = jis_level, "Chunk ingested");
        Ok(content_hash)
    }

    /// Ingest with a full JIS policy (not just clearance level)
    pub fn ingest_with_policy(
        &self,
        id: &str,
        embedding: Vec<u8>,
        content: Vec<u8>,
        policy: JisPolicy,
        source: Option<&str>,
    ) -> CortexResult<ContentHash> {
        let mut envelope = Envelope::new(id);
        if let Some(src) = source {
            envelope = envelope.with_source(src);
        }

        envelope.add_block(EnvelopeBlock::new_embedding(embedding));

        let content_hash = ContentHash::compute(&content);
        envelope.add_block(EnvelopeBlock::new_content(content, policy.min_clearance));

        let stored = StoredChunk { envelope, policy };
        let bytes = serde_json::to_vec(&stored)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        self.db
            .insert(id.as_bytes(), bytes)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        Ok(content_hash)
    }

    /// Query chunks with JIS-gated access. Returns only accessible content.
    pub fn query(
        &self,
        chunk_ids: &[&str],
        claim: &JisClaim,
    ) -> CortexResult<QueryResult> {
        let mut accessible = Vec::new();
        let mut denied = 0usize;

        for id in chunk_ids {
            let Some(bytes) = self.db.get(id.as_bytes())
                .map_err(|e| CortexError::Storage(e.to_string()))? else {
                continue;
            };

            let stored: StoredChunk = serde_json::from_slice(&bytes)?;
            let verdict = JisGate::evaluate(claim, &stored.policy);

            if verdict.allowed {
                if let Some(content_block) = stored.envelope.content(claim.clearance) {
                    accessible.push((content_block.data.clone(), stored.policy.min_clearance));
                }
            } else {
                denied += 1;
                tracing::debug!(
                    id = *id,
                    actor = claim.actor,
                    denials = ?verdict.denials,
                    "JIS access denied"
                );
            }
        }

        let total_matched = accessible.len() + denied;

        // Process all accessible chunks through the airlock
        let (contents, session) = self.airlock.process_chunks(
            &accessible,
            &claim.actor,
            claim.clearance,
            |plaintext| Ok(plaintext.to_vec()),
        )?;

        let chunks: Vec<AccessedChunk> = contents
            .into_iter()
            .enumerate()
            .map(|(i, data)| {
                let hash = ContentHash::compute(&data);
                AccessedChunk {
                    id: chunk_ids.get(i).unwrap_or(&"unknown").to_string(),
                    content: data,
                    content_hash: hash,
                    jis_level: accessible.get(i).map(|(_, l)| *l).unwrap_or(0),
                }
            })
            .collect();

        Ok(QueryResult {
            chunks,
            total_matched,
            total_denied: denied,
            session,
        })
    }

    /// Count total stored chunks
    pub fn count(&self) -> usize {
        self.db.len()
    }

    /// Flush to disk
    pub fn flush(&self) -> CortexResult<()> {
        self.db
            .flush()
            .map_err(|e| CortexError::Storage(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> CortexStore {
        let dir = tempfile::tempdir().unwrap();
        CortexStore::open(dir.path().to_str().unwrap()).unwrap()
    }

    #[test]
    fn test_ingest_and_query() {
        let store = temp_store();

        store.ingest(
            "doc_001",
            vec![1, 2, 3, 4], // embedding
            b"Public knowledge base article".to_vec(),
            0, // JIS 0
            Some("wiki"),
        ).unwrap();

        store.ingest(
            "doc_002",
            vec![5, 6, 7, 8],
            b"Confidential M&A strategy".to_vec(),
            3, // JIS 3
            Some("strategy-db"),
        ).unwrap();

        assert_eq!(store.count(), 2);

        // Intern (JIS 1) queries both
        let claim = JisClaim::new("intern@company.com", 1);
        let result = store.query(&["doc_001", "doc_002"], &claim).unwrap();

        assert_eq!(result.chunks.len(), 1); // Only doc_001
        assert_eq!(result.total_denied, 1); // doc_002 denied
        assert_eq!(
            String::from_utf8_lossy(&result.chunks[0].content),
            "Public knowledge base article"
        );
    }

    #[test]
    fn test_partner_full_access() {
        let store = temp_store();

        store.ingest("pub", vec![1], b"public".to_vec(), 0, None).unwrap();
        store.ingest("conf", vec![2], b"confidential".to_vec(), 2, None).unwrap();
        store.ingest("secret", vec![3], b"top secret".to_vec(), 3, None).unwrap();

        let claim = JisClaim::new("partner@company.com", 3);
        let result = store.query(&["pub", "conf", "secret"], &claim).unwrap();

        assert_eq!(result.chunks.len(), 3); // All accessible
        assert_eq!(result.total_denied, 0);
    }

    #[test]
    fn test_policy_based_access() {
        let store = temp_store();

        let policy = JisPolicy::clearance(2)
            .with_roles(vec!["partner".into()])
            .with_geos(vec!["NL".into(), "DE".into()]);

        store.ingest_with_policy(
            "eu_strategy",
            vec![1, 2],
            b"EU M&A playbook".to_vec(),
            policy,
            Some("strategy"),
        ).unwrap();

        // NL partner: access granted
        let nl_partner = JisClaim::new("partner@nl.com", 3)
            .with_role("partner")
            .with_geo(vec!["NL".into()]);

        // Clearance check passes (3 >= 2), but full policy check
        // happens at JIS gate level. The store query uses clearance only
        // for envelope block access after policy gate.
        let result = store.query(&["eu_strategy"], &nl_partner).unwrap();
        assert_eq!(result.chunks.len(), 1);
    }
}
