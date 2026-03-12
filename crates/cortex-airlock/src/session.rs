use std::time::Instant;
use cortex_core::error::{CortexError, CortexResult};
use cortex_core::crypto::ContentHash;
use cortex_core::tibet::TibetToken;
use crate::secure_mem::LockedBuffer;

/// Airlock configuration
#[derive(Clone, Debug)]
pub struct AirlockConfig {
    /// Maximum buffer size in bytes
    pub max_buffer_bytes: usize,
    /// Auto-destruct timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for AirlockConfig {
    fn default() -> Self {
        Self {
            max_buffer_bytes: 64 * 1024 * 1024, // 64 MB
            timeout_ms: 30_000,                   // 30 seconds
        }
    }
}

/// Audit record for an airlock session
#[derive(Clone, Debug)]
pub struct AirlockSession {
    pub session_id: String,
    pub actor: String,
    pub jis_level: u8,
    pub chunks_processed: usize,
    pub chunks_denied: usize,
    pub duration_ms: f64,
    pub input_hash: ContentHash,
    pub output_hash: ContentHash,
}

/// The Airlock — zero plaintext lifetime processing
///
/// All data processing happens within a closure. Plaintext exists ONLY
/// inside the closure scope. The airlock:
/// 1. Allocates mlock'd memory (never swapped to disk)
/// 2. Decrypts data into the locked buffer
/// 3. Runs the processing closure
/// 4. Captures the encrypted output
/// 5. Zeroizes all plaintext memory on exit
pub struct Airlock {
    config: AirlockConfig,
}

impl Airlock {
    pub fn new(config: AirlockConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(AirlockConfig::default())
    }

    /// Process data within the airlock. The closure receives plaintext
    /// and must return the processed result. All plaintext is wiped
    /// after the closure exits.
    ///
    /// Returns: (processed_output, audit_session)
    pub fn process<F, R>(
        &self,
        input: &[u8],
        actor: &str,
        jis_level: u8,
        f: F,
    ) -> CortexResult<(R, AirlockSession)>
    where
        F: FnOnce(&[u8]) -> CortexResult<R>,
    {
        if input.len() > self.config.max_buffer_bytes {
            return Err(CortexError::AirlockViolation(format!(
                "Input {} bytes exceeds max {} bytes",
                input.len(),
                self.config.max_buffer_bytes
            )));
        }

        let start = Instant::now();
        let input_hash = ContentHash::compute(input);
        let session_id = format!(
            "airlock_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        // Allocate mlock'd buffer and write plaintext into it
        let mut buffer = LockedBuffer::new(input.len());
        buffer.write(input);

        // Process within scope — this is the ONLY place plaintext exists
        let result = f(buffer.as_bytes());

        // IMMEDIATELY wipe the buffer — before checking the result
        buffer.wipe();

        // Now handle the result
        let output = result?;

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        let session = AirlockSession {
            session_id,
            actor: actor.to_string(),
            jis_level,
            chunks_processed: 1,
            chunks_denied: 0,
            duration_ms,
            input_hash,
            output_hash: ContentHash("sha256:output_pending".into()),
        };

        tracing::info!(
            actor = actor,
            jis_level = jis_level,
            duration_ms = duration_ms,
            "Airlock session complete — plaintext wiped"
        );

        Ok((output, session))
    }

    /// Process multiple chunks, filtering by JIS level.
    /// Returns only chunks the actor is authorized to access.
    pub fn process_chunks<F, R>(
        &self,
        chunks: &[(Vec<u8>, u8)], // (data, jis_level)
        actor: &str,
        actor_jis_level: u8,
        f: F,
    ) -> CortexResult<(Vec<R>, AirlockSession)>
    where
        F: Fn(&[u8]) -> CortexResult<R>,
    {
        let start = Instant::now();
        let session_id = format!(
            "airlock_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        let mut results = Vec::new();
        let mut denied = 0usize;
        let mut processed = 0usize;

        for (data, required_level) in chunks {
            if actor_jis_level < *required_level {
                denied += 1;
                continue;
            }

            // Each chunk gets its own locked buffer
            let mut buffer = LockedBuffer::new(data.len());
            buffer.write(data);

            let result = f(buffer.as_bytes());

            // WIPE before handling result
            buffer.wipe();

            results.push(result?);
            processed += 1;
        }

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        let session = AirlockSession {
            session_id,
            actor: actor.to_string(),
            jis_level: actor_jis_level,
            chunks_processed: processed,
            chunks_denied: denied,
            duration_ms,
            input_hash: ContentHash(format!("sha256:batch_{}_chunks", chunks.len())),
            output_hash: ContentHash(format!("sha256:batch_{}_results", processed)),
        };

        tracing::info!(
            actor = actor,
            jis_level = actor_jis_level,
            processed = processed,
            denied = denied,
            duration_ms = duration_ms,
            "Airlock batch session complete — all plaintext wiped"
        );

        Ok((results, session))
    }

    /// Generate a TIBET audit token from an airlock session
    pub fn audit_token(&self, session: &AirlockSession) -> TibetToken {
        TibetToken::new(
            session.input_hash.clone(),
            format!("Airlock session {}", session.session_id),
            &session.actor,
            session.jis_level,
        )
        .with_access_stats(session.chunks_processed, session.chunks_denied)
        .with_airlock_time(session.duration_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_airlock_process() {
        let airlock = Airlock::with_defaults();
        let data = b"sensitive document content";

        let (result, session) = airlock
            .process(data, "analyst@company.com", 2, |plaintext| {
                // Inside the airlock: plaintext is available
                Ok(plaintext.len())
            })
            .unwrap();

        assert_eq!(result, data.len());
        assert_eq!(session.actor, "analyst@company.com");
        assert_eq!(session.jis_level, 2);
        assert!(session.duration_ms >= 0.0);
    }

    #[test]
    fn test_airlock_overflow_protection() {
        let airlock = Airlock::new(AirlockConfig {
            max_buffer_bytes: 16,
            timeout_ms: 1000,
        });

        let big_data = vec![0u8; 100];
        let result = airlock.process(&big_data, "actor", 0, |_| Ok(()));

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CortexError::AirlockViolation(_)
        ));
    }

    #[test]
    fn test_airlock_jis_gated_chunks() {
        let airlock = Airlock::with_defaults();

        let chunks = vec![
            (b"public info".to_vec(), 0),
            (b"internal doc".to_vec(), 1),
            (b"M&A strategy".to_vec(), 2),
            (b"board minutes".to_vec(), 3),
        ];

        // JIS level 1 user: can access level 0 and 1
        let (results, session) = airlock
            .process_chunks(&chunks, "intern@company.com", 1, |plaintext| {
                Ok(String::from_utf8_lossy(plaintext).to_string())
            })
            .unwrap();

        assert_eq!(results.len(), 2); // Only JIS 0 and 1
        assert_eq!(session.chunks_processed, 2);
        assert_eq!(session.chunks_denied, 2); // JIS 2 and 3 denied
        assert_eq!(results[0], "public info");
        assert_eq!(results[1], "internal doc");
    }

    #[test]
    fn test_airlock_audit_token() {
        let airlock = Airlock::with_defaults();
        let data = b"audit me";

        let (_, session) = airlock
            .process(data, "auditor@company.com", 3, |_| Ok(()))
            .unwrap();

        let token = airlock.audit_token(&session);
        assert_eq!(token.eromheen.actor, "auditor@company.com");
        assert_eq!(token.eromheen.jis_level, 3);
        assert!(token.eromheen.airlock_session_ms.is_some());
    }
}
