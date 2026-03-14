"""
TIBET Token — Provenance token with Ed25519 signing.

Every action in Cortex generates a TibetToken with:
- ERIN: content hash (what's IN the action)
- ERAAN: references (what's attached)
- EROMHEEN: context (who, JIS level, stats)
- ERACHTER: intent (why)

Tokens can be signed with Ed25519 for cryptographic non-repudiation.

Note: For production key management, use the Rust crate `cortex-core`.
This Python implementation uses the `cryptography` library for signing.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


@dataclass
class Eromheen:
    """Context surrounding a TIBET action."""
    actor: str
    jis_level: int = 0
    chunks_accessed: int = 0
    chunks_denied: int = 0
    airlock_session_ms: Optional[float] = None


@dataclass
class TibetToken:
    """TIBET provenance token with optional Ed25519 signing."""
    token_id: str
    parent_id: Optional[str]
    timestamp: str
    erin: str  # content hash
    eraan: list = field(default_factory=list)
    eromheen: Eromheen = field(default_factory=lambda: Eromheen(actor="unknown"))
    erachter: str = ""
    signature: Optional[bytes] = None

    @classmethod
    def create(
        cls,
        erin: str,
        erachter: str,
        actor: str,
        jis_level: int = 0,
    ) -> "TibetToken":
        now = datetime.now(timezone.utc)
        token_id = f"tibet_{int(now.timestamp() * 1e9)}"
        return cls(
            token_id=token_id,
            parent_id=None,
            timestamp=now.isoformat(),
            erin=erin,
            eromheen=Eromheen(actor=actor, jis_level=jis_level),
            erachter=erachter,
        )

    def with_parent(self, parent_id: str) -> "TibetToken":
        self.parent_id = parent_id
        return self

    def with_access_stats(self, accessed: int, denied: int) -> "TibetToken":
        self.eromheen.chunks_accessed = accessed
        self.eromheen.chunks_denied = denied
        return self

    def signable_bytes(self) -> bytes:
        """Serialize everything except the signature for signing."""
        data = {
            "token_id": self.token_id,
            "parent_id": self.parent_id,
            "timestamp": self.timestamp,
            "erin": self.erin,
            "eraan": self.eraan,
            "eromheen": {
                "actor": self.eromheen.actor,
                "jis_level": self.eromheen.jis_level,
                "chunks_accessed": self.eromheen.chunks_accessed,
                "chunks_denied": self.eromheen.chunks_denied,
                "airlock_session_ms": self.eromheen.airlock_session_ms,
            },
            "erachter": self.erachter,
            "signature": None,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def sign(self, private_key: Ed25519PrivateKey) -> "TibetToken":
        """Sign this token with an Ed25519 private key."""
        self.signature = private_key.sign(self.signable_bytes())
        return self

    def verify_signature(self, public_key: Ed25519PublicKey) -> bool:
        """Verify the token's signature. Returns True if valid."""
        if self.signature is None:
            return False
        try:
            public_key.verify(self.signature, self.signable_bytes())
            return True
        except InvalidSignature:
            return False

    def is_signed(self) -> bool:
        return self.signature is not None

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "parent_id": self.parent_id,
            "timestamp": self.timestamp,
            "erin": self.erin,
            "eraan": self.eraan,
            "eromheen": {
                "actor": self.eromheen.actor,
                "jis_level": self.eromheen.jis_level,
                "chunks_accessed": self.eromheen.chunks_accessed,
                "chunks_denied": self.eromheen.chunks_denied,
                "airlock_session_ms": self.eromheen.airlock_session_ms,
            },
            "erachter": self.erachter,
            "signature": self.signature.hex() if self.signature else None,
        }


@dataclass
class Provenance:
    """Append-only provenance chain with signature verification."""
    chain: list = field(default_factory=list)

    def append(self, token: TibetToken):
        self.chain.append(token)

    def latest(self) -> Optional[TibetToken]:
        return self.chain[-1] if self.chain else None

    def verify_chain(self) -> bool:
        """Verify parent-child linkage."""
        for i in range(1, len(self.chain)):
            if self.chain[i].parent_id != self.chain[i - 1].token_id:
                return False
        return True

    def verify_signatures(self, public_key: Ed25519PublicKey) -> bool:
        """Verify chain integrity AND all token signatures."""
        if not self.verify_chain():
            return False
        return all(t.verify_signature(public_key) for t in self.chain)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 keypair for token signing."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def content_hash(data: bytes) -> str:
    """Compute SHA-256 content hash."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
