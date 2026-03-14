//! Integration tests for TIBET Cortex — full flow:
//! ingest → search → audit → verify → token signing

use cortex_core::crypto::{ContentHash, KeyPair};
use cortex_core::tibet::{TibetToken, Provenance};
use cortex_jis::{JisClaim, JisPolicy};
use cortex_store::CortexStore;
use cortex_audit::AuditTrail;

/// Helper: encode f32 slice to LE bytes (embedding format)
fn f32_to_bytes(vals: &[f32]) -> Vec<u8> {
    vals.iter().flat_map(|f| f.to_le_bytes()).collect()
}

// ─── Full pipeline: ingest → search → audit → verify ───

#[test]
fn test_full_pipeline_ingest_search_audit_verify() {
    let store_dir = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();

    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();
    let mut trail = AuditTrail::open(audit_dir.path().to_str().unwrap()).unwrap();

    // Ingest 3 documents at different JIS levels
    let emb_pub = f32_to_bytes(&[1.0, 0.0, 0.0]);
    let emb_int = f32_to_bytes(&[0.8, 0.6, 0.0]);
    let emb_sec = f32_to_bytes(&[0.0, 0.0, 1.0]);

    store.ingest("wiki_article", emb_pub, b"Public knowledge base article about Rust".to_vec(), 0, Some("wiki")).unwrap();
    store.ingest("internal_memo", emb_int, b"Internal memo: Q3 strategy review".to_vec(), 1, Some("internal")).unwrap();
    store.ingest("board_minutes", emb_sec, b"Board minutes: M&A target list for 2026".to_vec(), 3, Some("board")).unwrap();

    assert_eq!(store.count(), 3);

    // Query as intern (clearance 0): should only get public doc
    let intern_claim = JisClaim::new("intern@company.com", 0);
    let query_emb = f32_to_bytes(&[1.0, 0.0, 0.0]); // similar to pub doc
    let result = store.search(&query_emb, &intern_claim, 10).unwrap();

    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].id, "wiki_article");
    assert!(result.hits[0].score > 0.99); // near-identical embedding
    assert_eq!(result.total_denied, 2); // internal + board denied

    // Record to audit trail
    let query_hash = ContentHash::compute(b"rust knowledge");
    let response_hash = ContentHash::compute(&result.hits[0].content);
    let entry = trail.record_session(&result.session, query_hash, response_hash).unwrap();
    assert_eq!(entry.chunks_accessed, 1);

    // Query as partner (clearance 3): gets all docs
    let partner_claim = JisClaim::new("partner@company.com", 3);
    let result2 = store.search(&query_emb, &partner_claim, 10).unwrap();

    assert_eq!(result2.hits.len(), 3);
    assert_eq!(result2.total_denied, 0);

    // Record second query to audit
    let query_hash2 = ContentHash::compute(b"all documents");
    let response_hash2 = ContentHash::compute(b"full results");
    trail.record_session(&result2.session, query_hash2, response_hash2).unwrap();

    // Verify audit chain integrity
    assert_eq!(trail.chain_len(), 2);
    assert!(trail.verify_chain());

    // Verify stats
    let stats = trail.stats().unwrap();
    assert_eq!(stats.total_queries, 2);
    assert!(stats.chain_intact);
}

// ─── Token signing throughout the pipeline ───

#[test]
fn test_signed_audit_trail() {
    let kp = KeyPair::generate();
    let audit_dir = tempfile::tempdir().unwrap();
    let mut trail = AuditTrail::open(audit_dir.path().to_str().unwrap()).unwrap();

    // Simulate 5 airlock sessions, recording each
    for i in 0..5 {
        let session = cortex_airlock::AirlockSession {
            session_id: format!("session_{i}"),
            actor: format!("user_{}", i % 2),
            jis_level: (i % 4) as u8,
            chunks_processed: i + 1,
            chunks_denied: i,
            duration_ms: 0.5 * i as f64,
            input_hash: ContentHash::compute(format!("query_{i}").as_bytes()),
            output_hash: ContentHash::compute(format!("result_{i}").as_bytes()),
        };

        let query_hash = ContentHash::compute(format!("q_{i}").as_bytes());
        let response_hash = ContentHash::compute(format!("r_{i}").as_bytes());
        trail.record_session(&session, query_hash, response_hash).unwrap();
    }

    // Chain should be intact
    assert_eq!(trail.chain_len(), 5);
    assert!(trail.verify_chain());

    // Now create a separate signed provenance chain from the audit tokens
    let mut signed_chain = Provenance::new();
    for token in &trail.chain().chain {
        let signed = token.clone().sign(&kp);
        assert!(signed.is_signed());
        assert!(signed.verify_signature(&kp).is_ok());
        signed_chain.append(signed);
    }

    // The signed chain preserves parent linkage from the audit trail
    assert!(signed_chain.verify_chain());
    assert!(signed_chain.verify_signatures(&kp));

    // Wrong key should fail
    let wrong_kp = KeyPair::generate();
    assert!(!signed_chain.verify_signatures(&wrong_kp));
}

// ─── JIS policy + vector search combined ───

#[test]
fn test_policy_gated_vector_search() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();

    // EU-only strategy doc with role + geo gating
    let policy = JisPolicy::clearance(2)
        .with_roles(vec!["partner".into()])
        .with_geos(vec!["NL".into(), "DE".into()]);

    let emb = f32_to_bytes(&[0.5, 0.5, 0.0]);
    store.ingest_with_policy(
        "eu_playbook",
        emb.clone(),
        b"EU M&A playbook - confidential".to_vec(),
        policy,
        Some("strategy"),
    ).unwrap();

    // Public doc (no policy restrictions)
    store.ingest("faq", f32_to_bytes(&[0.5, 0.5, 0.0]), b"FAQ: How to use Cortex".to_vec(), 0, None).unwrap();

    // NL partner with clearance 3 — should get both
    let nl_partner = JisClaim::new("partner@nl.com", 3)
        .with_role("partner")
        .with_geo(vec!["NL".into()]);
    let result = store.search(&emb, &nl_partner, 10).unwrap();
    assert_eq!(result.hits.len(), 2);

    // US analyst with clearance 3 — denied by geo restriction, gets only FAQ
    let us_analyst = JisClaim::new("analyst@us.com", 3)
        .with_role("analyst")
        .with_geo(vec!["US".into()]);
    let result = store.search(&emb, &us_analyst, 10).unwrap();
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].id, "faq");
    assert_eq!(result.total_denied, 1);
}

// ─── Airlock isolation test ───

#[test]
fn test_airlock_processes_through_search() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();

    // Ingest a sensitive doc
    let emb = f32_to_bytes(&[1.0, 0.0, 0.0]);
    store.ingest("sensitive", emb.clone(), b"Top secret financial data".to_vec(), 2, None).unwrap();

    // Search with sufficient clearance
    let claim = JisClaim::new("authorized@company.com", 3);
    let result = store.search(&emb, &claim, 5).unwrap();

    // Airlock session should be recorded
    assert_eq!(result.session.chunks_processed, 1);
    assert!(result.session.duration_ms >= 0.0);
    assert_eq!(result.session.actor, "authorized@company.com");

    // Content should be accessible
    assert_eq!(result.hits.len(), 1);
    assert_eq!(
        String::from_utf8_lossy(&result.hits[0].content),
        "Top secret financial data"
    );
}

// ─── Edge cases ───

#[test]
fn test_empty_store_search() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();

    let query = f32_to_bytes(&[1.0, 0.0, 0.0]);
    let claim = JisClaim::new("user", 0);
    let result = store.search(&query, &claim, 10).unwrap();

    assert_eq!(result.hits.len(), 0);
    assert_eq!(result.total_scanned, 0);
}

#[test]
fn test_token_sign_verify_roundtrip() {
    let kp = KeyPair::generate();

    // Create a token, sign it, serialize to JSON, deserialize, verify
    let hash = ContentHash::compute(b"integration test data");
    let token = TibetToken::new(hash, "integration test", "root_idd", 2).sign(&kp);

    let json = serde_json::to_string(&token).unwrap();
    let restored: TibetToken = serde_json::from_str(&json).unwrap();

    assert!(restored.is_signed());
    assert!(restored.verify_signature(&kp).is_ok());
}

#[test]
fn test_cosine_similarity_identical_vectors() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();

    let emb = f32_to_bytes(&[0.3, 0.4, 0.5]);
    store.ingest("doc", emb.clone(), b"test content".to_vec(), 0, None).unwrap();

    let claim = JisClaim::new("user", 0);
    let result = store.search(&emb, &claim, 1).unwrap();

    assert_eq!(result.hits.len(), 1);
    // Identical vectors → cosine similarity = 1.0
    assert!((result.hits[0].score - 1.0).abs() < 0.001);
}

#[test]
fn test_cosine_similarity_orthogonal_vectors() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();

    let emb = f32_to_bytes(&[1.0, 0.0, 0.0]);
    store.ingest("doc", emb, b"content".to_vec(), 0, None).unwrap();

    // Orthogonal query
    let query = f32_to_bytes(&[0.0, 1.0, 0.0]);
    let claim = JisClaim::new("user", 0);
    let result = store.search(&query, &claim, 1).unwrap();

    assert_eq!(result.hits.len(), 1);
    // Orthogonal vectors → cosine similarity = 0.0
    assert!(result.hits[0].score.abs() < 0.001);
}
