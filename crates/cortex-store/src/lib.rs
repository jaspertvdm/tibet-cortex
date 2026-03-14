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

/// A single search hit with similarity score
#[derive(Debug)]
pub struct SearchHit {
    pub id: String,
    pub score: f32,
    pub content: Vec<u8>,
    pub content_hash: ContentHash,
    pub jis_level: u8,
}

/// Search result with ranked hits and JIS filtering
#[derive(Debug)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub total_scanned: usize,
    pub total_denied: usize,
    pub session: AirlockSession,
}

/// Decode raw bytes (little-endian f32) into a Vec<f32>
fn bytes_to_f32(data: &[u8]) -> Vec<f32> {
    data.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Cosine similarity between two f32 vectors. Returns 0.0 on zero-length.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 { 0.0 } else { dot / denom }
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

    /// Semantic search: find the top-K most similar chunks by cosine similarity.
    ///
    /// `query_embedding` is raw f32 LE bytes (same format as stored embeddings).
    /// Returns ranked hits filtered by JIS claim, processed through the Airlock.
    pub fn search(
        &self,
        query_embedding: &[u8],
        claim: &JisClaim,
        top_k: usize,
    ) -> CortexResult<SearchResult> {
        let query_vec = bytes_to_f32(query_embedding);
        if query_vec.is_empty() {
            return Err(CortexError::Storage("Empty query embedding".into()));
        }

        // Scan all chunks, compute similarity on the embedding block (JIS 0)
        let mut scored: Vec<(String, f32, StoredChunk)> = Vec::new();
        let mut denied = 0usize;

        for entry in self.db.iter() {
            let (key, val) = entry.map_err(|e| CortexError::Storage(e.to_string()))?;
            let id = String::from_utf8_lossy(&key).to_string();
            let stored: StoredChunk = match serde_json::from_slice(&val) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // JIS gate check
            let verdict = JisGate::evaluate(claim, &stored.policy);
            if !verdict.allowed {
                denied += 1;
                continue;
            }

            // Compute similarity on the embedding (JIS 0 — always readable)
            if let Some(emb_block) = stored.envelope.embedding() {
                let emb_vec = bytes_to_f32(&emb_block.data);
                let score = cosine_similarity(&query_vec, &emb_vec);
                scored.push((id, score, stored));
            }
        }

        let total_scanned = scored.len() + denied;

        // Sort descending by score, take top_k
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);

        // Process accessible content through the airlock
        let airlock_input: Vec<(Vec<u8>, u8)> = scored
            .iter()
            .filter_map(|(_, _, stored)| {
                stored.envelope.content(claim.clearance)
                    .map(|block| (block.data.clone(), stored.policy.min_clearance))
            })
            .collect();

        let (contents, session) = self.airlock.process_chunks(
            &airlock_input,
            &claim.actor,
            claim.clearance,
            |plaintext| Ok(plaintext.to_vec()),
        )?;

        let hits: Vec<SearchHit> = contents
            .into_iter()
            .enumerate()
            .map(|(i, data)| {
                let hash = ContentHash::compute(&data);
                let (id, score, stored) = &scored[i];
                SearchHit {
                    id: id.clone(),
                    score: *score,
                    content: data,
                    content_hash: hash,
                    jis_level: stored.policy.min_clearance,
                }
            })
            .collect();

        Ok(SearchResult {
            hits,
            total_scanned,
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

    /// Helper: encode f32 slice to LE bytes (embedding format)
    fn f32_to_bytes(vals: &[f32]) -> Vec<u8> {
        vals.iter().flat_map(|f| f.to_le_bytes()).collect()
    }

    #[test]
    fn test_search_cosine_ranking() {
        let store = temp_store();

        // Three docs with different embeddings (3-dimensional)
        let emb_a = f32_to_bytes(&[1.0, 0.0, 0.0]); // points right
        let emb_b = f32_to_bytes(&[0.7, 0.7, 0.0]); // 45 degrees
        let emb_c = f32_to_bytes(&[0.0, 1.0, 0.0]); // points up

        store.ingest("a", emb_a, b"Doc A".to_vec(), 0, None).unwrap();
        store.ingest("b", emb_b, b"Doc B".to_vec(), 0, None).unwrap();
        store.ingest("c", emb_c, b"Doc C".to_vec(), 0, None).unwrap();

        // Query pointing right — should rank A > B > C
        let query = f32_to_bytes(&[1.0, 0.0, 0.0]);
        let claim = JisClaim::new("user", 0);
        let result = store.search(&query, &claim, 3).unwrap();

        assert_eq!(result.hits.len(), 3);
        assert_eq!(result.hits[0].id, "a"); // most similar
        assert_eq!(result.hits[1].id, "b"); // medium
        assert_eq!(result.hits[2].id, "c"); // least similar
        assert!(result.hits[0].score > result.hits[1].score);
        assert!(result.hits[1].score > result.hits[2].score);
    }

    #[test]
    fn test_search_jis_filtering() {
        let store = temp_store();

        let emb = f32_to_bytes(&[1.0, 0.0, 0.0]);
        store.ingest("public", emb.clone(), b"Public doc".to_vec(), 0, None).unwrap();
        store.ingest("secret", emb.clone(), b"Secret doc".to_vec(), 3, None).unwrap();

        // Low clearance user — should only see public
        let claim = JisClaim::new("intern", 0);
        let result = store.search(&emb, &claim, 10).unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].id, "public");
        assert_eq!(result.total_denied, 1);
    }

    #[test]
    fn test_search_top_k_limit() {
        let store = temp_store();

        for i in 0..10 {
            let emb = f32_to_bytes(&[1.0, i as f32 * 0.01, 0.0]);
            store.ingest(&format!("doc_{i}"), emb, format!("Doc {i}").into_bytes(), 0, None).unwrap();
        }

        let query = f32_to_bytes(&[1.0, 0.0, 0.0]);
        let claim = JisClaim::new("user", 0);
        let result = store.search(&query, &claim, 3).unwrap();

        assert_eq!(result.hits.len(), 3);
        assert_eq!(result.total_scanned, 10);
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
