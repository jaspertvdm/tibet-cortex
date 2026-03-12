//! TIBET Cortex Audit — Blackbox-met-window audit trails
//!
//! The auditor can see:
//! - WHO accessed data (actor)
//! - WHEN it was accessed (timestamp)
//! - HOW MUCH data was touched (chunks accessed/denied)
//! - WHAT JIS level was used (clearance)
//! - WHETHER integrity holds (TIBET hash chain)
//!
//! The auditor CANNOT see:
//! - The actual content (unless they have matching JIS level)
//! - The query itself (only its hash)
//!
//! Audit trails are append-only TIBET chains stored in sled,
//! with optional tibet-vault integration for time-locked compliance.

use cortex_core::tibet::{TibetToken, Provenance};
use cortex_core::crypto::ContentHash;
use cortex_core::error::{CortexError, CortexResult};
use cortex_airlock::AirlockSession;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// An audit entry — the "window" into the blackbox
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub token: TibetToken,
    pub query_hash: ContentHash,
    pub chunks_accessed: usize,
    pub chunks_denied: usize,
    pub response_hash: ContentHash,
    pub airlock_duration_ms: f64,
    pub timestamp: DateTime<Utc>,
}

/// The Audit Trail — append-only log backed by sled
pub struct AuditTrail {
    db: sled::Db,
    chain: Provenance,
}

/// Audit statistics for compliance reporting
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_queries: usize,
    pub total_chunks_accessed: usize,
    pub total_chunks_denied: usize,
    pub unique_actors: usize,
    pub chain_intact: bool,
    pub first_entry: Option<DateTime<Utc>>,
    pub last_entry: Option<DateTime<Utc>>,
}

impl AuditTrail {
    pub fn open(path: &str) -> CortexResult<Self> {
        let db = sled::open(path)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        // Load existing chain
        let chain = if let Some(bytes) = db.get(b"__chain__")
            .map_err(|e| CortexError::Storage(e.to_string()))? {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Provenance::new()
        };

        Ok(Self { db, chain })
    }

    /// Record an airlock session as an audit entry
    pub fn record_session(
        &mut self,
        session: &AirlockSession,
        query_hash: ContentHash,
        response_hash: ContentHash,
    ) -> CortexResult<AuditEntry> {
        let mut token = TibetToken::new(
            query_hash.clone(),
            format!("Query processed via airlock {}", session.session_id),
            &session.actor,
            session.jis_level,
        )
        .with_access_stats(session.chunks_processed, session.chunks_denied)
        .with_airlock_time(session.duration_ms);

        // Chain to previous token
        if let Some(prev) = self.chain.latest() {
            token = token.with_parent(&prev.token_id);
        }

        let entry = AuditEntry {
            token: token.clone(),
            query_hash,
            chunks_accessed: session.chunks_processed,
            chunks_denied: session.chunks_denied,
            response_hash,
            airlock_duration_ms: session.duration_ms,
            timestamp: Utc::now(),
        };

        // Store entry
        let entry_bytes = serde_json::to_vec(&entry)?;
        self.db
            .insert(token.token_id.as_bytes(), entry_bytes)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        // Update chain
        self.chain.append(token);
        let chain_bytes = serde_json::to_vec(&self.chain)?;
        self.db
            .insert(b"__chain__", chain_bytes)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        self.db
            .flush()
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        Ok(entry)
    }

    /// Record a custom audit event (e.g., system prompt modification)
    pub fn record_event(
        &mut self,
        actor: &str,
        jis_level: u8,
        event_hash: ContentHash,
        description: &str,
    ) -> CortexResult<AuditEntry> {
        let mut token = TibetToken::new(
            event_hash.clone(),
            description,
            actor,
            jis_level,
        );

        if let Some(prev) = self.chain.latest() {
            token = token.with_parent(&prev.token_id);
        }

        let entry = AuditEntry {
            token: token.clone(),
            query_hash: event_hash,
            chunks_accessed: 0,
            chunks_denied: 0,
            response_hash: ContentHash("sha256:event".into()),
            airlock_duration_ms: 0.0,
            timestamp: Utc::now(),
        };

        let entry_bytes = serde_json::to_vec(&entry)?;
        self.db
            .insert(token.token_id.as_bytes(), entry_bytes)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        self.chain.append(token);
        let chain_bytes = serde_json::to_vec(&self.chain)?;
        self.db
            .insert(b"__chain__", chain_bytes)
            .map_err(|e| CortexError::Storage(e.to_string()))?;

        Ok(entry)
    }

    /// Verify the entire audit chain is unbroken
    pub fn verify_chain(&self) -> bool {
        self.chain.verify_chain()
    }

    /// Get audit statistics
    pub fn stats(&self) -> CortexResult<AuditStats> {
        let mut total_accessed = 0usize;
        let mut total_denied = 0usize;
        let mut actors = std::collections::HashSet::new();

        let entries: Vec<AuditEntry> = self.db
            .iter()
            .filter_map(|r| r.ok())
            .filter(|(k, _)| k.as_ref() != b"__chain__")
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();

        for entry in &entries {
            total_accessed += entry.chunks_accessed;
            total_denied += entry.chunks_denied;
            actors.insert(entry.token.eromheen.actor.clone());
        }

        Ok(AuditStats {
            total_queries: entries.len(),
            total_chunks_accessed: total_accessed,
            total_chunks_denied: total_denied,
            unique_actors: actors.len(),
            chain_intact: self.verify_chain(),
            first_entry: entries.iter().map(|e| e.timestamp).min(),
            last_entry: entries.iter().map(|e| e.timestamp).max(),
        })
    }

    /// Get the full provenance chain (for auditors with sufficient JIS level)
    pub fn chain(&self) -> &Provenance {
        &self.chain
    }

    /// Get chain length
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_trail() -> AuditTrail {
        let dir = tempfile::tempdir().unwrap();
        AuditTrail::open(dir.path().to_str().unwrap()).unwrap()
    }

    #[test]
    fn test_record_and_verify() {
        let mut trail = temp_trail();

        let session = AirlockSession {
            session_id: "test_001".into(),
            actor: "analyst@company.com".into(),
            jis_level: 2,
            chunks_processed: 5,
            chunks_denied: 3,
            duration_ms: 12.5,
            input_hash: ContentHash("sha256:input".into()),
            output_hash: ContentHash("sha256:output".into()),
        };

        let entry = trail.record_session(
            &session,
            ContentHash("sha256:query_hash".into()),
            ContentHash("sha256:response_hash".into()),
        ).unwrap();

        assert_eq!(entry.chunks_accessed, 5);
        assert_eq!(entry.chunks_denied, 3);
        assert_eq!(trail.chain_len(), 1);
        assert!(trail.verify_chain());
    }

    #[test]
    fn test_chain_integrity() {
        let mut trail = temp_trail();

        for i in 0..5 {
            let session = AirlockSession {
                session_id: format!("session_{i}"),
                actor: "user@test.com".into(),
                jis_level: 1,
                chunks_processed: i,
                chunks_denied: 0,
                duration_ms: 1.0,
                input_hash: ContentHash(format!("sha256:input_{i}")),
                output_hash: ContentHash(format!("sha256:output_{i}")),
            };

            trail.record_session(
                &session,
                ContentHash(format!("sha256:query_{i}")),
                ContentHash(format!("sha256:response_{i}")),
            ).unwrap();
        }

        assert_eq!(trail.chain_len(), 5);
        assert!(trail.verify_chain());
    }

    #[test]
    fn test_audit_stats() {
        let mut trail = temp_trail();

        for actor in &["alice@co.com", "bob@co.com", "alice@co.com"] {
            let session = AirlockSession {
                session_id: "s".into(),
                actor: actor.to_string(),
                jis_level: 1,
                chunks_processed: 10,
                chunks_denied: 5,
                duration_ms: 1.0,
                input_hash: ContentHash("sha256:in".into()),
                output_hash: ContentHash("sha256:out".into()),
            };

            trail.record_session(
                &session,
                ContentHash("sha256:q".into()),
                ContentHash("sha256:r".into()),
            ).unwrap();
        }

        let stats = trail.stats().unwrap();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.total_chunks_accessed, 30);
        assert_eq!(stats.total_chunks_denied, 15);
        assert_eq!(stats.unique_actors, 2);
        assert!(stats.chain_intact);
    }
}
