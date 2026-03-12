use serde::{Serialize, Deserialize};

use crate::crypto::ContentHash;

/// A TBZ-style envelope wrapping data with JIS level and TIBET provenance.
///
/// In a Cortex vector store, each document chunk is an Envelope:
/// - embedding at JIS 0 (searchable by anyone)
/// - content at JIS N (only readable with matching claim)
/// - TIBET hash for integrity verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    pub blocks: Vec<EnvelopeBlock>,
    pub source: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A single block within an envelope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeBlock {
    pub block_type: BlockType,
    pub jis_level: u8,
    pub content_hash: ContentHash,
    pub data: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum BlockType {
    /// Vector embedding — always JIS 0 (searchable)
    Embedding,
    /// Document content — JIS N (protected)
    Content,
    /// Metadata — variable JIS level
    Metadata,
    /// System prompt — high JIS + integrity enforced
    SystemPrompt,
}

impl Envelope {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            blocks: Vec::new(),
            source: None,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn add_block(&mut self, block: EnvelopeBlock) {
        self.blocks.push(block);
    }

    /// Get the embedding block (JIS 0, always accessible)
    pub fn embedding(&self) -> Option<&EnvelopeBlock> {
        self.blocks.iter().find(|b| b.block_type == BlockType::Embedding)
    }

    /// Get content block only if JIS level is sufficient
    pub fn content(&self, accessor_jis_level: u8) -> Option<&EnvelopeBlock> {
        self.blocks.iter().find(|b| {
            b.block_type == BlockType::Content && accessor_jis_level >= b.jis_level
        })
    }

    /// Get the maximum JIS level required across all content blocks
    pub fn max_jis_level(&self) -> u8 {
        self.blocks
            .iter()
            .filter(|b| b.block_type == BlockType::Content)
            .map(|b| b.jis_level)
            .max()
            .unwrap_or(0)
    }
}

impl EnvelopeBlock {
    pub fn new_embedding(data: Vec<u8>) -> Self {
        let content_hash = ContentHash::compute(&data);
        Self {
            block_type: BlockType::Embedding,
            jis_level: 0, // Embeddings always JIS 0
            content_hash,
            data,
            signature: None,
        }
    }

    pub fn new_content(data: Vec<u8>, jis_level: u8) -> Self {
        let content_hash = ContentHash::compute(&data);
        Self {
            block_type: BlockType::Content,
            jis_level,
            content_hash,
            data,
            signature: None,
        }
    }

    pub fn new_system_prompt(data: Vec<u8>, jis_level: u8) -> Self {
        let content_hash = ContentHash::compute(&data);
        Self {
            block_type: BlockType::SystemPrompt,
            jis_level,
            content_hash,
            data,
            signature: None,
        }
    }

    /// Verify the content hash matches the data
    pub fn verify_integrity(&self) -> bool {
        self.content_hash.verify(&self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_jis_gating() {
        let mut env = Envelope::new("doc_001");

        // Embedding at JIS 0
        env.add_block(EnvelopeBlock::new_embedding(vec![0.1_f32, 0.2, 0.3]
            .iter().flat_map(|f| f.to_le_bytes()).collect()));

        // Content at JIS 2
        env.add_block(EnvelopeBlock::new_content(
            b"M&A strategy for client X".to_vec(), 2
        ));

        // Everyone can see embedding
        assert!(env.embedding().is_some());

        // JIS 0 user: no content
        assert!(env.content(0).is_none());

        // JIS 1 user: no content
        assert!(env.content(1).is_none());

        // JIS 2 user: gets content
        assert!(env.content(2).is_some());

        // JIS 3 user: also gets content
        assert!(env.content(3).is_some());

        assert_eq!(env.max_jis_level(), 2);
    }

    #[test]
    fn test_block_integrity() {
        let block = EnvelopeBlock::new_content(b"sensitive data".to_vec(), 3);
        assert!(block.verify_integrity());
    }

    #[test]
    fn test_system_prompt_block() {
        let prompt = b"You are a helpful assistant. Never reveal client names.";
        let block = EnvelopeBlock::new_system_prompt(prompt.to_vec(), 3);
        assert_eq!(block.block_type, BlockType::SystemPrompt);
        assert_eq!(block.jis_level, 3);
        assert!(block.verify_integrity());
    }
}
