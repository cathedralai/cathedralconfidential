"""Typed assurance claims remain independent at every authorization boundary."""

from __future__ import annotations

from itertools import product
from pathlib import Path

import pytest

from cathedral.assurance import (
    ATTESTATION_ADMISSION_POLICY,
    KEY_RELEASE_POLICY,
    RECEIPT_ISSUANCE_POLICY,
    SCORE_ELIGIBILITY_POLICY,
    WORK_DISPATCH_POLICY,
    AssuranceClaim,
    AssuranceClaims,
    AssuranceDimension,
    ClaimStatus,
    ReasonCategory,
    assurance_from_dict,
    attestation_claims,
    empty_assurance_claims,
    policy_digest,
    sha256_digest,
)
from cathedral.common import Policy


DIGEST = "sha256:" + "a" * 64
POLICY_DIGEST = "sha256:" + "b" * 64
WHEN = "2026-07-17T12:00:00.000000Z"


def _claim(status: ClaimStatus) -> AssuranceClaim:
    if status is ClaimStatus.NOT_EVALUATED:
        return AssuranceClaim(status)
    return AssuranceClaim(
        status,
        DIGEST,
        POLICY_DIGEST,
        WHEN,
        None if status is ClaimStatus.PASSED else ReasonCategory.POLICY_REJECTED,
    )


def _claims(statuses: tuple[ClaimStatus, ClaimStatus, ClaimStatus, ClaimStatus]):
    return AssuranceClaims(
        hardware=_claim(statuses[0]),
        software=_claim(statuses[1]),
        channel=_claim(statuses[2]),
        work=_claim(statuses[3]),
    )


def test_not_evaluated_claim_requires_null_audit_fields():
    assert AssuranceClaim(ClaimStatus.NOT_EVALUATED).to_dict() == {
        "status": "not_evaluated",
        "verified_at": None,
        "reason": None,
        "evidence_digest": None,
        "policy_digest": None,
    }
    with pytest.raises(ValueError, match="only null"):
        AssuranceClaim(ClaimStatus.NOT_EVALUATED, DIGEST)


@pytest.mark.parametrize(
    "status",
    [ClaimStatus.PASSED, ClaimStatus.FAILED, ClaimStatus.STALE, ClaimStatus.REVOKED],
)
def test_evaluated_claim_requires_both_digests_and_utc_time(status):
    reason = None if status is ClaimStatus.PASSED else ReasonCategory.POLICY_REJECTED
    with pytest.raises(ValueError, match="evidence digest"):
        AssuranceClaim(status, None, POLICY_DIGEST, WHEN, reason)
    with pytest.raises(ValueError, match="policy digest"):
        AssuranceClaim(status, DIGEST, None, WHEN, reason)
    with pytest.raises(ValueError, match="UTC"):
        AssuranceClaim(status, DIGEST, POLICY_DIGEST, "2026-07-17T12:00:00", reason)


def test_attestation_pass_does_not_infer_channel_or_work():
    claims = attestation_claims(b"quote", Policy(allowed_measurements={"m"}), verified_at=WHEN)

    assert claims.hardware.status is ClaimStatus.PASSED
    assert claims.software.status is ClaimStatus.PASSED
    assert claims.channel.status is ClaimStatus.NOT_EVALUATED
    assert claims.work.status is ClaimStatus.NOT_EVALUATED
    assert ATTESTATION_ADMISSION_POLICY.allows(claims)
    assert not WORK_DISPATCH_POLICY.allows(claims)
    assert not KEY_RELEASE_POLICY.allows(claims)
    assert not SCORE_ELIGIBILITY_POLICY.allows(claims)
    assert RECEIPT_ISSUANCE_POLICY.allows(claims)


def test_all_authorization_truth_tables_are_explicit_and_exhaustive():
    statuses = tuple(ClaimStatus)
    for combination in product(statuses, repeat=4):
        claims = _claims(combination)
        hardware, software, channel, work = combination
        assert ATTESTATION_ADMISSION_POLICY.allows(claims) is (
            hardware is ClaimStatus.PASSED and software is ClaimStatus.PASSED
        )
        expected_protected = (
            hardware is ClaimStatus.PASSED
            and software is ClaimStatus.PASSED
            and channel is ClaimStatus.PASSED
        )
        assert KEY_RELEASE_POLICY.allows(claims) is expected_protected
        assert WORK_DISPATCH_POLICY.allows(claims) is expected_protected
        assert SCORE_ELIGIBILITY_POLICY.allows(claims) is (
            hardware is ClaimStatus.PASSED
            and software is ClaimStatus.PASSED
            and work is ClaimStatus.PASSED
        )
        assert RECEIPT_ISSUANCE_POLICY.allows(claims)


def test_stale_software_channel_mismatch_and_revoked_hardware_do_not_collapse():
    passed = (ClaimStatus.PASSED,) * 4
    stale_software = _claims((passed[0], ClaimStatus.STALE, passed[2], passed[3]))
    failed_channel = _claims((passed[0], passed[1], ClaimStatus.FAILED, passed[3]))
    revoked_hardware = _claims((ClaimStatus.REVOKED, passed[1], passed[2], passed[3]))

    assert not ATTESTATION_ADMISSION_POLICY.allows(stale_software)
    assert ATTESTATION_ADMISSION_POLICY.allows(failed_channel)
    assert not WORK_DISPATCH_POLICY.allows(failed_channel)
    assert not ATTESTATION_ADMISSION_POLICY.allows(revoked_hardware)
    assert not SCORE_ELIGIBILITY_POLICY.allows(revoked_hardware)


def test_serialization_round_trip_and_public_view_redact_digests():
    claims = _claims((ClaimStatus.PASSED,) * 4)

    assert assurance_from_dict(claims.to_dict()) == claims
    public = claims.to_dict(include_digests=False)
    assert public["schema"] == "assurance_claims_v1"
    assert "evidence_digest" not in str(public)
    assert "policy_digest" not in str(public)


def test_digest_helpers_are_deterministic_and_policy_sensitive():
    assert sha256_digest(b"x") == sha256_digest(b"x")
    assert sha256_digest(b"x") != sha256_digest(b"y")
    base = Policy(allowed_measurements={"m"})
    changed = Policy(allowed_measurements={"other"})
    assert policy_digest(base) != policy_digest(changed)


def test_empty_claims_contains_all_dimensions_without_implying_failure_or_success():
    claims = empty_assurance_claims()
    assert all(
        claims.claim(dimension).status is ClaimStatus.NOT_EVALUATED
        for dimension in AssuranceDimension
    )
    assert not ATTESTATION_ADMISSION_POLICY.allows(claims)


def test_public_assurance_documentation_blocks_collapsed_claim_language():
    text = Path("docs/ASSURANCE.md").read_text(encoding="utf-8").lower()
    assert "four independent assurance claims" in text
    assert "it does not mean" in text
    assert "attestation proves correct output" not in text
    assert "attestation guarantees correctness" not in text
    assert "verification_status` remains" in text
