"""
JIS — Multi-dimensional Joint Identity Sectors

JIS is not a single number. It's a multi-dimensional identity claim:
- Role: partner, analyst, intern
- Department: strategy, finance, engineering
- Clearance: numeric level 0-255
- Time: valid_from / valid_until
- Geo: country/region restrictions

All dimensions must match for access.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class JisDenialReason(Enum):
    CLEARANCE_TOO_LOW = "clearance_too_low"
    ROLE_NOT_ALLOWED = "role_not_allowed"
    DEPARTMENT_NOT_ALLOWED = "department_not_allowed"
    GEO_RESTRICTED = "geo_restricted"
    CLAIM_EXPIRED = "claim_expired"
    CLAIM_NOT_YET_VALID = "claim_not_yet_valid"
    DATA_NOT_YET_AVAILABLE = "data_not_yet_available"
    DATA_EXPIRED = "data_expired"


@dataclass
class JisDenial:
    reason: JisDenialReason
    detail: str


@dataclass
class JisVerdict:
    allowed: bool
    claim_actor: str
    denials: list


@dataclass
class JisClaim:
    """A JIS identity claim — multi-dimensional access credential."""
    actor: str
    clearance: int = 0
    role: Optional[str] = None
    department: Optional[str] = None
    geo: Optional[list] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "actor": self.actor,
            "clearance": self.clearance,
            "role": self.role,
            "department": self.department,
            "geo": self.geo,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


@dataclass
class JisPolicy:
    """A JIS policy attached to data — defines who can access it."""
    min_clearance: int = 0
    allowed_roles: list = field(default_factory=list)
    allowed_departments: list = field(default_factory=list)
    allowed_geos: list = field(default_factory=list)
    available_from: Optional[datetime] = None
    available_until: Optional[datetime] = None

    @classmethod
    def public(cls) -> "JisPolicy":
        return cls()

    @classmethod
    def clearance(cls, level: int) -> "JisPolicy":
        return cls(min_clearance=level)


class JisGate:
    """The JIS Gate — evaluates claims against policies."""

    @staticmethod
    def evaluate(claim: JisClaim, policy: JisPolicy) -> JisVerdict:
        denials = []
        now = datetime.now(timezone.utc)

        # 1. Clearance level
        if claim.clearance < policy.min_clearance:
            denials.append(JisDenial(
                JisDenialReason.CLEARANCE_TOO_LOW,
                f"Required {policy.min_clearance}, got {claim.clearance}",
            ))

        # 2. Role
        if policy.allowed_roles:
            if not claim.role or claim.role not in policy.allowed_roles:
                denials.append(JisDenial(
                    JisDenialReason.ROLE_NOT_ALLOWED,
                    f"Role '{claim.role}' not in {policy.allowed_roles}",
                ))

        # 3. Department
        if policy.allowed_departments:
            if not claim.department or claim.department not in policy.allowed_departments:
                denials.append(JisDenial(
                    JisDenialReason.DEPARTMENT_NOT_ALLOWED,
                    f"Dept '{claim.department}' not in {policy.allowed_departments}",
                ))

        # 4. Geo
        if policy.allowed_geos:
            if not claim.geo or not any(g in policy.allowed_geos for g in claim.geo):
                denials.append(JisDenial(
                    JisDenialReason.GEO_RESTRICTED,
                    f"Geo {claim.geo} not in {policy.allowed_geos}",
                ))

        # 5. Claim time validity
        if claim.valid_until and now > claim.valid_until:
            denials.append(JisDenial(
                JisDenialReason.CLAIM_EXPIRED,
                f"Expired at {claim.valid_until.isoformat()}",
            ))
        if claim.valid_from and now < claim.valid_from:
            denials.append(JisDenial(
                JisDenialReason.CLAIM_NOT_YET_VALID,
                f"Valid from {claim.valid_from.isoformat()}",
            ))

        # 6. Data time availability
        if policy.available_from and now < policy.available_from:
            denials.append(JisDenial(
                JisDenialReason.DATA_NOT_YET_AVAILABLE,
                f"Available from {policy.available_from.isoformat()}",
            ))
        if policy.available_until and now > policy.available_until:
            denials.append(JisDenial(
                JisDenialReason.DATA_EXPIRED,
                f"Expired at {policy.available_until.isoformat()}",
            ))

        return JisVerdict(
            allowed=len(denials) == 0,
            claim_actor=claim.actor,
            denials=denials,
        )

    @staticmethod
    def is_allowed(claim: JisClaim, policy: JisPolicy) -> bool:
        return JisGate.evaluate(claim, policy).allowed
