"""Typed assurance claims and explicit eligibility policies.

Hardware authenticity, approved software, protected-channel ownership, and
verified work are independent facts.  This module deliberately has no generic
``verified`` or ``overall_status`` field: every authorization site must name the
claim dimensions it requires.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Mapping


ASSURANCE_SCHEMA = "assurance_claims_v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AssuranceDimension(str, Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"
    CHANNEL = "channel"
    WORK = "work"


class ClaimStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    PASSED = "passed"
    FAILED = "failed"
    STALE = "stale"
    REVOKED = "revoked"


class ReasonCategory(str, Enum):
    EVIDENCE_INVALID = "evidence_invalid"
    POLICY_REJECTED = "policy_rejected"
    CHANNEL_MISMATCH = "channel_mismatch"
    WORK_INVALID = "work_invalid"
    EVIDENCE_STALE = "evidence_stale"
    POLICY_REVOKED = "policy_revoked"
    IDENTITY_CONFLICT = "identity_conflict"
    INTERNAL_ERROR = "internal_error"


def sha256_digest(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("digest input must be bytes")
    return "sha256:" + hashlib.sha256(value).hexdigest()


CHANNEL_BINDING_POLICY_DIGEST = sha256_digest(
    b"cathedral-channel-binding-policy-v2"
)


def policy_digest(policy: object) -> str:
    """Digest the admission-relevant local policy until registry #25 replaces it."""

    body = {
        "allowed_firmware": sorted(getattr(policy, "allowed_firmware", set())),
        "allowed_measurements": sorted(getattr(policy, "allowed_measurements", set())),
        "min_tcb": getattr(policy, "min_tcb", 0),
        "registry_digest": getattr(policy, "registry_digest", None),
        "registry_profile_ids": list(getattr(policy, "registry_profile_ids", ())),
        "registry_release": getattr(policy, "registry_release", None),
        "tdx_allowed_advisories": sorted(
            getattr(policy, "tdx_allowed_advisories", set())
        ),
        "tdx_allowed_tcb_statuses": sorted(
            getattr(policy, "tdx_allowed_tcb_statuses", set())
        ),
        "tdx_strict": getattr(policy, "tdx_strict", False),
        "version": 1,
    }
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return sha256_digest(encoded)


def verified_at_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _valid_utc_timestamp(value: str) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


@dataclass(frozen=True)
class AssuranceClaim:
    status: ClaimStatus
    evidence_digest: str | None = None
    policy_digest: str | None = None
    verified_at: str | None = None
    reason: ReasonCategory | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ClaimStatus):
            raise ValueError("assurance claim status must be a ClaimStatus")
        if self.status is ClaimStatus.NOT_EVALUATED:
            if any(
                value is not None
                for value in (
                    self.evidence_digest,
                    self.policy_digest,
                    self.verified_at,
                    self.reason,
                )
            ):
                raise ValueError("not_evaluated claims must carry only null audit fields")
            return
        if not isinstance(self.evidence_digest, str) or _DIGEST.fullmatch(
            self.evidence_digest
        ) is None:
            raise ValueError("evaluated claims require a canonical evidence digest")
        if not isinstance(self.policy_digest, str) or _DIGEST.fullmatch(
            self.policy_digest
        ) is None:
            raise ValueError("evaluated claims require a canonical policy digest")
        if not isinstance(self.verified_at, str) or not _valid_utc_timestamp(
            self.verified_at
        ):
            raise ValueError("evaluated claims require a UTC verification timestamp")
        if self.status is ClaimStatus.PASSED and self.reason is not None:
            raise ValueError("passed claims cannot carry a failure reason")
        if self.status is not ClaimStatus.PASSED and not isinstance(
            self.reason, ReasonCategory
        ):
            raise ValueError("failed, stale, and revoked claims require a safe reason")

    def to_dict(self, *, include_digests: bool = True) -> dict[str, str | None]:
        result: dict[str, str | None] = {
            "status": self.status.value,
            "verified_at": self.verified_at,
            "reason": self.reason.value if self.reason else None,
        }
        if include_digests:
            result["evidence_digest"] = self.evidence_digest
            result["policy_digest"] = self.policy_digest
        return result


def not_evaluated_claim() -> AssuranceClaim:
    return AssuranceClaim(ClaimStatus.NOT_EVALUATED)


@dataclass(frozen=True)
class AssuranceClaims:
    hardware: AssuranceClaim
    software: AssuranceClaim
    channel: AssuranceClaim
    work: AssuranceClaim
    schema: str = ASSURANCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ASSURANCE_SCHEMA:
            raise ValueError("unsupported assurance claims schema")
        if any(
            not isinstance(claim, AssuranceClaim)
            for claim in (self.hardware, self.software, self.channel, self.work)
        ):
            raise ValueError("all four assurance claims are required")

    def claim(self, dimension: AssuranceDimension) -> AssuranceClaim:
        if not isinstance(dimension, AssuranceDimension):
            raise ValueError("unknown assurance dimension")
        return getattr(self, dimension.value)

    def with_claim(
        self, dimension: AssuranceDimension, claim: AssuranceClaim
    ) -> AssuranceClaims:
        if not isinstance(claim, AssuranceClaim):
            raise ValueError("replacement must be an AssuranceClaim")
        return replace(self, **{dimension.value: claim})

    def to_dict(self, *, include_digests: bool = True) -> dict[str, object]:
        return {
            "schema": self.schema,
            "claims": {
                dimension.value: self.claim(dimension).to_dict(
                    include_digests=include_digests
                )
                for dimension in AssuranceDimension
            },
        }


def empty_assurance_claims() -> AssuranceClaims:
    return AssuranceClaims(
        hardware=not_evaluated_claim(),
        software=not_evaluated_claim(),
        channel=not_evaluated_claim(),
        work=not_evaluated_claim(),
    )


@dataclass(frozen=True)
class EligibilityDecision:
    eligible: bool
    required: tuple[AssuranceDimension, ...]
    unsatisfied: tuple[AssuranceDimension, ...]


@dataclass(frozen=True)
class EligibilityPolicy:
    name: str
    required_passed: tuple[AssuranceDimension, ...]

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 128:
            raise ValueError("eligibility policy name must be bounded and nonempty")
        if len(set(self.required_passed)) != len(self.required_passed):
            raise ValueError("eligibility policy cannot repeat a dimension")
        if any(
            not isinstance(dimension, AssuranceDimension)
            for dimension in self.required_passed
        ):
            raise ValueError("eligibility policy contains an unknown dimension")

    def evaluate(self, claims: AssuranceClaims | None) -> EligibilityDecision:
        unsatisfied = tuple(
            dimension
            for dimension in self.required_passed
            if claims is None or claims.claim(dimension).status is not ClaimStatus.PASSED
        )
        return EligibilityDecision(not unsatisfied, self.required_passed, unsatisfied)

    def allows(self, claims: AssuranceClaims | None) -> bool:
        return self.evaluate(claims).eligible


ATTESTATION_ADMISSION_POLICY = EligibilityPolicy(
    "attestation_admission_v1",
    (AssuranceDimension.HARDWARE, AssuranceDimension.SOFTWARE),
)
KEY_RELEASE_POLICY = EligibilityPolicy(
    "key_release_v1",
    (
        AssuranceDimension.HARDWARE,
        AssuranceDimension.SOFTWARE,
        AssuranceDimension.CHANNEL,
    ),
)
WORK_DISPATCH_POLICY = EligibilityPolicy(
    "work_dispatch_v1",
    (
        AssuranceDimension.HARDWARE,
        AssuranceDimension.SOFTWARE,
        AssuranceDimension.CHANNEL,
    ),
)
SCORE_ELIGIBILITY_POLICY = EligibilityPolicy(
    "score_eligibility_v1",
    (
        AssuranceDimension.HARDWARE,
        AssuranceDimension.SOFTWARE,
        AssuranceDimension.WORK,
    ),
)
RECEIPT_ISSUANCE_POLICY = EligibilityPolicy("receipt_issuance_v1", ())


def attestation_claims(
    evidence: bytes,
    policy: object,
    *,
    verified_at: str | None = None,
    hardware_status: ClaimStatus = ClaimStatus.PASSED,
    hardware_reason: ReasonCategory | None = None,
    software_status: ClaimStatus = ClaimStatus.PASSED,
    software_reason: ReasonCategory | None = None,
) -> AssuranceClaims:
    when = verified_at or verified_at_now()
    evidence_id = sha256_digest(evidence)
    policy_id = policy_digest(policy)
    hardware = AssuranceClaim(
        hardware_status,
        evidence_id,
        policy_id,
        when,
        hardware_reason,
    )
    software = (
        not_evaluated_claim()
        if software_status is ClaimStatus.NOT_EVALUATED
        else AssuranceClaim(
            software_status,
            evidence_id,
            policy_id,
            when,
            software_reason,
        )
    )
    return AssuranceClaims(
        hardware=hardware,
        software=software,
        channel=not_evaluated_claim(),
        work=not_evaluated_claim(),
    )


def evaluated_claim(
    status: ClaimStatus,
    evidence: bytes,
    policy_id: str,
    *,
    verified_at: str | None = None,
    reason: ReasonCategory | None = None,
) -> AssuranceClaim:
    return AssuranceClaim(
        status,
        sha256_digest(evidence),
        policy_id,
        verified_at or verified_at_now(),
        reason,
    )


def with_verified_channel(
    claims: AssuranceClaims,
    binding_material: bytes,
    *,
    verified_at: str | None = None,
) -> AssuranceClaims:
    """Attach a passed channel claim after live-key and quote checks agree."""

    channel = evaluated_claim(
        ClaimStatus.PASSED,
        binding_material,
        CHANNEL_BINDING_POLICY_DIGEST,
        verified_at=verified_at,
    )
    return claims.with_claim(AssuranceDimension.CHANNEL, channel)


def assurance_from_dict(value: Mapping[str, object]) -> AssuranceClaims:
    if value.get("schema") != ASSURANCE_SCHEMA or not isinstance(
        value.get("claims"), Mapping
    ):
        raise ValueError("invalid assurance claims document")
    raw_claims = value["claims"]
    assert isinstance(raw_claims, Mapping)

    def parse(dimension: AssuranceDimension) -> AssuranceClaim:
        raw = raw_claims.get(dimension.value)
        if not isinstance(raw, Mapping):
            raise ValueError("assurance document must contain all four claims")
        try:
            status = ClaimStatus(raw.get("status"))
            reason_value = raw.get("reason")
            reason = ReasonCategory(reason_value) if reason_value is not None else None
        except (TypeError, ValueError) as exc:
            raise ValueError("assurance document contains an unknown status or reason") from exc
        return AssuranceClaim(
            status=status,
            evidence_digest=raw.get("evidence_digest"),  # type: ignore[arg-type]
            policy_digest=raw.get("policy_digest"),  # type: ignore[arg-type]
            verified_at=raw.get("verified_at"),  # type: ignore[arg-type]
            reason=reason,
        )

    parsed_claims = {
        dimension.value: parse(dimension) for dimension in AssuranceDimension
    }
    return AssuranceClaims(**parsed_claims)
