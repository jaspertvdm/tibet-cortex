"""
TBZ-style envelopes for TIBET Cortex.

Each document chunk is an Envelope:
- embedding at JIS 0 (searchable by anyone)
- content at JIS N (only readable with matching claim)
- TIBET hash for integrity verification
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class BlockType(Enum):
    EMBEDDING = "embedding"
    CONTENT = "content"
    METADATA = "metadata"
    SYSTEM_PROMPT = "system_prompt"


@dataclass
class EnvelopeBlock:
    """A single block within an envelope."""
    block_type: BlockType
    jis_level: int
    data: bytes
    content_hash: str = ""
    signature: Optional[bytes] = None

    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        return f"sha256:{hashlib.sha256(self.data).hexdigest()}"

    def verify_integrity(self) -> bool:
        return self.content_hash == self._compute_hash()

    @classmethod
    def new_embedding(cls, data: bytes) -> "EnvelopeBlock":
        return cls(block_type=BlockType.EMBEDDING, jis_level=0, data=data)

    @classmethod
    def new_content(cls, data: bytes, jis_level: int) -> "EnvelopeBlock":
        return cls(block_type=BlockType.CONTENT, jis_level=jis_level, data=data)

    @classmethod
    def new_system_prompt(cls, data: bytes, jis_level: int) -> "EnvelopeBlock":
        return cls(block_type=BlockType.SYSTEM_PROMPT, jis_level=jis_level, data=data)


@dataclass
class Envelope:
    """A TBZ-style envelope wrapping data with JIS level and TIBET provenance."""
    id: str
    blocks: list = field(default_factory=list)
    source: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_block(self, block: EnvelopeBlock):
        self.blocks.append(block)

    def embedding(self) -> Optional[EnvelopeBlock]:
        return next((b for b in self.blocks if b.block_type == BlockType.EMBEDDING), None)

    def content(self, accessor_jis_level: int) -> Optional[EnvelopeBlock]:
        return next(
            (b for b in self.blocks
             if b.block_type == BlockType.CONTENT and accessor_jis_level >= b.jis_level),
            None,
        )

    def max_jis_level(self) -> int:
        content_levels = [
            b.jis_level for b in self.blocks if b.block_type == BlockType.CONTENT
        ]
        return max(content_levels) if content_levels else 0
