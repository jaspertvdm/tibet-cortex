"""
TIBET Cortex — Zero-trust AI knowledge processing

JIS-gated vector storage, Airlock-protected inference, TIBET-audited provenance.
Data that protects itself.

Usage:
    from cortex import JisClaim, JisPolicy, JisGate, Envelope, AuditTrail

    # Create an identity claim
    claim = JisClaim(
        actor="analyst@company.com",
        clearance=2,
        role="analyst",
        department="strategy",
        geo=["NL", "DE"],
    )

    # Define a policy for sensitive data
    policy = JisPolicy(
        min_clearance=2,
        allowed_roles=["analyst", "partner"],
        allowed_departments=["strategy"],
        allowed_geos=["NL", "DE", "FR"],
    )

    # Check access
    verdict = JisGate.evaluate(claim, policy)
    print(f"Allowed: {verdict.allowed}")
    print(f"Denials: {verdict.denials}")
"""

__version__ = "0.1.0"

from cortex.jis import JisClaim, JisPolicy, JisGate, JisVerdict, JisDenialReason
from cortex.envelope import Envelope, EnvelopeBlock, BlockType
from cortex.audit import AuditTrail, AuditEntry
from cortex.airlock import Airlock, AirlockSession

__all__ = [
    "JisClaim", "JisPolicy", "JisGate", "JisVerdict", "JisDenialReason",
    "Envelope", "EnvelopeBlock", "BlockType",
    "AuditTrail", "AuditEntry",
    "Airlock", "AirlockSession",
]
