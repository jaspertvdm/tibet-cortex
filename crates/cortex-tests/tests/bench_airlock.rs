//! Airlock latency benchmark — measures overhead of mlock'd processing.
//!
//! This test measures the real-world latency impact of the Airlock
//! on query processing, answering: "How much overhead does volatile
//! RAM protection add to real-time RAG responses?"

use cortex_airlock::Airlock;
use cortex_core::crypto::ContentHash;
use cortex_jis::JisClaim;
use cortex_store::CortexStore;
use std::time::Instant;

/// Helper: encode f32 slice to LE bytes
fn f32_to_bytes(vals: &[f32]) -> Vec<u8> {
    vals.iter().flat_map(|f| f.to_le_bytes()).collect()
}

#[test]
fn bench_airlock_single_chunk() {
    let airlock = Airlock::with_defaults();

    // Simulate a typical RAG chunk (~4KB, like a paragraph)
    let chunk = vec![0x42u8; 4096];
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = airlock.process(&chunk, "bench@test", 2, |data| {
            // Simulate minimal processing: just hash the data
            Ok(ContentHash::compute(data))
        });
    }
    let elapsed = start.elapsed();

    let per_op_us = elapsed.as_micros() as f64 / iterations as f64;
    let per_op_ms = per_op_us / 1000.0;

    println!();
    println!("=== AIRLOCK LATENCY BENCHMARK ===");
    println!("  Chunk size:     4 KB");
    println!("  Iterations:     {iterations}");
    println!("  Total time:     {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Per operation:  {per_op_us:.1}us ({per_op_ms:.4}ms)");
    println!("  Throughput:     {:.0} ops/sec", 1_000_000.0 / per_op_us);
    println!();

    // In debug mode: < 10ms, in release: < 0.1ms typically
    assert!(per_op_ms < 10.0, "Airlock too slow: {per_op_ms:.4}ms per op");
}

#[test]
fn bench_airlock_batch_chunks() {
    let airlock = Airlock::with_defaults();

    // Simulate a typical RAG response: 10 chunks of ~4KB each
    let chunks: Vec<(Vec<u8>, u8)> = (0..10)
        .map(|i| (vec![i as u8; 4096], 0u8))
        .collect();

    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = airlock.process_chunks(&chunks, "bench@test", 3, |data| {
            Ok(ContentHash::compute(data))
        });
    }
    let elapsed = start.elapsed();

    let per_batch_us = elapsed.as_micros() as f64 / iterations as f64;
    let per_batch_ms = per_batch_us / 1000.0;
    let per_chunk_us = per_batch_us / 10.0;

    println!();
    println!("=== AIRLOCK BATCH BENCHMARK ===");
    println!("  Chunks/batch:   10 x 4KB");
    println!("  Iterations:     {iterations}");
    println!("  Total time:     {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Per batch:      {per_batch_us:.1}us ({per_batch_ms:.4}ms)");
    println!("  Per chunk:      {per_chunk_us:.1}us");
    println!("  Throughput:     {:.0} chunks/sec", 1_000_000.0 / per_chunk_us);
    println!();

    // In debug mode: < 50ms, in release: < 1ms typically
    assert!(per_batch_ms < 50.0, "Batch too slow: {per_batch_ms:.4}ms");
}

#[test]
fn bench_full_search_pipeline() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = CortexStore::open(store_dir.path().to_str().unwrap()).unwrap();

    // Ingest 100 documents (simulating a real knowledge base)
    for i in 0..100 {
        let angle = (i as f32) * 0.0628; // spread vectors
        let emb = f32_to_bytes(&[angle.cos(), angle.sin(), 0.1]);
        let content = format!("Document {i}: This is a test chunk for benchmarking the full search pipeline including JIS gate evaluation and airlock processing.");
        store.ingest(
            &format!("doc_{i:03}"),
            emb,
            content.into_bytes(),
            (i % 4) as u8, // JIS levels 0-3
            Some("bench"),
        ).unwrap();
    }

    assert_eq!(store.count(), 100);

    let query = f32_to_bytes(&[1.0, 0.0, 0.0]);
    let claim = JisClaim::new("bench@test", 3); // full access
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = store.search(&query, &claim, 5).unwrap();
    }
    let elapsed = start.elapsed();

    let per_search_us = elapsed.as_micros() as f64 / iterations as f64;
    let per_search_ms = per_search_us / 1000.0;

    println!();
    println!("=== FULL SEARCH PIPELINE BENCHMARK ===");
    println!("  Store size:     100 documents");
    println!("  Top-K:          5");
    println!("  JIS clearance:  3 (full access)");
    println!("  Iterations:     {iterations}");
    println!("  Total time:     {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Per search:     {per_search_us:.1}us ({per_search_ms:.4}ms)");
    println!("  Throughput:     {:.0} searches/sec", 1_000_000.0 / per_search_us);
    println!();
    println!("  Pipeline: scan 100 embeddings + JIS gate + cosine rank + airlock 5 chunks");
    println!();

    // Full pipeline should be < 50ms for 100 docs
    assert!(per_search_ms < 50.0, "Search too slow: {per_search_ms:.4}ms");
}
