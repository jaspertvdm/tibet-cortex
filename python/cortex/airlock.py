"""
TIBET Cortex Airlock — Zero plaintext lifetime processing (Python)

Note: The Rust implementation provides true mlock'd memory. This Python
wrapper provides the API and audit semantics. For production use with
memory guarantees, use the Rust crate `cortex-airlock`.
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass
class AirlockSession:
    """Audit record for an airlock session."""
    session_id: str
    actor: str
    jis_level: int
    chunks_processed: int
    chunks_denied: int
    duration_ms: float
    input_hash: str
    output_hash: str


class Airlock:
    """Zero plaintext lifetime processing.

    All data processing happens within a callback. The airlock
    generates audit tokens for every operation.
    """

    def __init__(self, max_buffer_bytes: int = 64 * 1024 * 1024):
        self.max_buffer_bytes = max_buffer_bytes

    def process(
        self,
        data: bytes,
        actor: str,
        jis_level: int,
        callback: Callable[[bytes], T],
    ) -> tuple[T, AirlockSession]:
        """Process data within the airlock.

        The callback receives the plaintext data. After the callback
        returns, the reference is discarded.
        """
        if len(data) > self.max_buffer_bytes:
            raise ValueError(
                f"Input {len(data)} bytes exceeds max {self.max_buffer_bytes}"
            )

        start = time.monotonic()
        input_hash = f"sha256:{hashlib.sha256(data).hexdigest()}"
        session_id = f"airlock_{int(time.time() * 1e9)}"

        # Process
        result = callback(data)

        duration_ms = (time.monotonic() - start) * 1000

        session = AirlockSession(
            session_id=session_id,
            actor=actor,
            jis_level=jis_level,
            chunks_processed=1,
            chunks_denied=0,
            duration_ms=duration_ms,
            input_hash=input_hash,
            output_hash="sha256:pending",
        )

        return result, session

    def process_chunks(
        self,
        chunks: list[tuple[bytes, int]],  # (data, jis_level)
        actor: str,
        actor_jis_level: int,
        callback: Callable[[bytes], T],
    ) -> tuple[list[T], AirlockSession]:
        """Process multiple chunks with JIS filtering."""
        start = time.monotonic()
        session_id = f"airlock_{int(time.time() * 1e9)}"
        results = []
        denied = 0

        for data, required_level in chunks:
            if actor_jis_level < required_level:
                denied += 1
                continue
            results.append(callback(data))

        duration_ms = (time.monotonic() - start) * 1000

        session = AirlockSession(
            session_id=session_id,
            actor=actor,
            jis_level=actor_jis_level,
            chunks_processed=len(results),
            chunks_denied=denied,
            duration_ms=duration_ms,
            input_hash=f"sha256:batch_{len(chunks)}_chunks",
            output_hash=f"sha256:batch_{len(results)}_results",
        )

        return results, session
