"""
TIBET Cortex Store — JIS-gated vector storage with cosine similarity search.

Stores document chunks as envelopes:
- Embeddings at JIS 0 (always searchable)
- Content at JIS N (gated by policy)
- Every search goes through the Airlock

Note: This is an in-memory store for Python usage. For persistent
sled-backed storage, use the Rust crate `cortex-store`.
"""

import math
import struct
from dataclasses import dataclass, field
from typing import Optional

from cortex.envelope import Envelope, EnvelopeBlock
from cortex.jis import JisClaim, JisPolicy, JisGate
from cortex.airlock import Airlock, AirlockSession


@dataclass
class StoredChunk:
    """A stored document chunk with its JIS policy."""
    id: str
    envelope: Envelope
    policy: JisPolicy


@dataclass
class SearchHit:
    """A single search hit with similarity score."""
    id: str
    score: float
    content: bytes
    content_hash: str
    jis_level: int


@dataclass
class SearchResult:
    """Search result with ranked hits and JIS filtering."""
    hits: list
    total_scanned: int
    total_denied: int
    session: AirlockSession


def _bytes_to_f32(data: bytes) -> list[float]:
    """Decode raw bytes (little-endian f32) into a list of floats."""
    count = len(data) // 4
    return list(struct.unpack(f"<{count}f", data[:count * 4]))


def _f32_to_bytes(vals: list[float]) -> bytes:
    """Encode float list to little-endian f32 bytes."""
    return struct.pack(f"<{len(vals)}f", *vals)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two float vectors."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    denom = norm_a * norm_b
    return dot / denom if denom > 0 else 0.0


class CortexStore:
    """In-memory JIS-gated vector store with cosine similarity search."""

    def __init__(self):
        self._chunks: dict[str, StoredChunk] = {}
        self._airlock = Airlock()

    def ingest(
        self,
        id: str,
        embedding: bytes,
        content: bytes,
        jis_level: int = 0,
        source: Optional[str] = None,
    ) -> str:
        """Ingest a document chunk with embedding and JIS-gated content."""
        envelope = Envelope(id=id, source=source)
        envelope.add_block(EnvelopeBlock.new_embedding(embedding))
        envelope.add_block(EnvelopeBlock.new_content(content, jis_level))

        self._chunks[id] = StoredChunk(
            id=id,
            envelope=envelope,
            policy=JisPolicy.clearance(jis_level),
        )
        return EnvelopeBlock.new_content(content, jis_level).content_hash

    def ingest_with_policy(
        self,
        id: str,
        embedding: bytes,
        content: bytes,
        policy: JisPolicy,
        source: Optional[str] = None,
    ) -> str:
        """Ingest with a full JIS policy (role, geo, time gating)."""
        envelope = Envelope(id=id, source=source)
        envelope.add_block(EnvelopeBlock.new_embedding(embedding))
        envelope.add_block(EnvelopeBlock.new_content(content, policy.min_clearance))

        self._chunks[id] = StoredChunk(
            id=id,
            envelope=envelope,
            policy=policy,
        )
        return EnvelopeBlock.new_content(content, policy.min_clearance).content_hash

    def search(
        self,
        query_embedding: bytes,
        claim: JisClaim,
        top_k: int = 5,
    ) -> SearchResult:
        """Semantic search: cosine similarity ranked, JIS-gated, Airlock-processed."""
        query_vec = _bytes_to_f32(query_embedding)
        if not query_vec:
            raise ValueError("Empty query embedding")

        scored = []
        denied = 0

        for chunk_id, chunk in self._chunks.items():
            # JIS gate check
            verdict = JisGate.evaluate(claim, chunk.policy)
            if not verdict.allowed:
                denied += 1
                continue

            # Compute similarity on embedding (JIS 0)
            emb_block = chunk.envelope.embedding()
            if emb_block:
                emb_vec = _bytes_to_f32(emb_block.data)
                score = cosine_similarity(query_vec, emb_vec)
                scored.append((chunk_id, score, chunk))

        total_scanned = len(scored) + denied

        # Sort descending by score, take top_k
        scored.sort(key=lambda x: x[1], reverse=True)
        scored = scored[:top_k]

        # Process through airlock
        airlock_input = []
        for _, _, chunk in scored:
            content_block = chunk.envelope.content(claim.clearance)
            if content_block:
                airlock_input.append((content_block.data, chunk.policy.min_clearance))

        contents, session = self._airlock.process_chunks(
            airlock_input, claim.actor, claim.clearance, lambda data: data
        )

        hits = []
        for i, content in enumerate(contents):
            import hashlib
            h = f"sha256:{hashlib.sha256(content).hexdigest()}"
            chunk_id, score, chunk = scored[i]
            hits.append(SearchHit(
                id=chunk_id,
                score=score,
                content=content,
                content_hash=h,
                jis_level=chunk.policy.min_clearance,
            ))

        return SearchResult(
            hits=hits,
            total_scanned=total_scanned,
            total_denied=denied,
            session=session,
        )

    def count(self) -> int:
        return len(self._chunks)
