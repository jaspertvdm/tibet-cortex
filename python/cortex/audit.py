"""
TIBET Cortex Audit — Blackbox-met-window audit trails

The auditor sees WHO/WHEN/HOW MUCH — not WHAT.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cortex.airlock import AirlockSession


@dataclass
class AuditEntry:
    """An audit entry — the 'window' into the blackbox."""
    token_id: str
    parent_id: Optional[str]
    actor: str
    jis_level: int
    query_hash: str
    chunks_accessed: int
    chunks_denied: int
    response_hash: str
    airlock_duration_ms: float
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "parent_id": self.parent_id,
            "actor": self.actor,
            "jis_level": self.jis_level,
            "query_hash": self.query_hash,
            "chunks_accessed": self.chunks_accessed,
            "chunks_denied": self.chunks_denied,
            "response_hash": self.response_hash,
            "airlock_duration_ms": self.airlock_duration_ms,
            "timestamp": self.timestamp,
        }


class AuditTrail:
    """Append-only audit trail with TIBET chain verification."""

    def __init__(self, path: str = ".cortex/audit.json"):
        self.path = Path(path)
        self.entries: list[AuditEntry] = []
        self._load()

    def _load(self):
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.entries = [AuditEntry(**e) for e in data.get("entries", [])]

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"entries": [e.to_dict() for e in self.entries]}
        self.path.write_text(json.dumps(data, indent=2))

    def record_session(
        self,
        session: AirlockSession,
        query_hash: str,
        response_hash: str,
    ) -> AuditEntry:
        now = datetime.now(timezone.utc)
        token_id = f"tibet_{int(now.timestamp() * 1e9)}"
        parent_id = self.entries[-1].token_id if self.entries else None

        entry = AuditEntry(
            token_id=token_id,
            parent_id=parent_id,
            actor=session.actor,
            jis_level=session.jis_level,
            query_hash=query_hash,
            chunks_accessed=session.chunks_processed,
            chunks_denied=session.chunks_denied,
            response_hash=response_hash,
            airlock_duration_ms=session.duration_ms,
            timestamp=now.isoformat(),
        )

        self.entries.append(entry)
        self._save()
        return entry

    def verify_chain(self) -> bool:
        """Verify the chain is unbroken."""
        for i in range(1, len(self.entries)):
            if self.entries[i].parent_id != self.entries[i - 1].token_id:
                return False
        return True

    def stats(self) -> dict:
        actors = set()
        total_accessed = 0
        total_denied = 0

        for e in self.entries:
            actors.add(e.actor)
            total_accessed += e.chunks_accessed
            total_denied += e.chunks_denied

        return {
            "total_queries": len(self.entries),
            "total_chunks_accessed": total_accessed,
            "total_chunks_denied": total_denied,
            "unique_actors": len(actors),
            "chain_intact": self.verify_chain(),
            "first_entry": self.entries[0].timestamp if self.entries else None,
            "last_entry": self.entries[-1].timestamp if self.entries else None,
        }
