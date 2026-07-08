"""MOCK attestation path (Phase-1-pending).

MOCK — the real hardware verifier (vendor crypto: AMD KDS, Intel DCAP/Trust
Authority, NVIDIA NRAS/nvtrust) lives in `cathedral/verify/__init__.py` and is
a Phase-1 stub. This module skips vendor crypto entirely but performs the
*real* REPORT_DATA binding + measurement/TCB policy checks using
`cathedral.common` logic, so it exercises the same admission contract the
hardware path will. See docs/DESIGN.md §6.
"""

from __future__ import annotations

from dataclasses import dataclass

from cathedral.common import Attested, EvidenceKind, Policy, Tier, report_data


@dataclass(frozen=True)
class MockEvidence:
    """Stand-in for a parsed, vendor-verified quote (MOCK, no crypto)."""

    kind: EvidenceKind
    tier: Tier
    chip_id: str
    measurement: str
    tcb: int
    miner_hotkey: str
    bound_report_data: bytes
    ssh_host_key: bytes | None = None


def mock_evidence(
    nonce: bytes,
    hotkey: str,
    *,
    kind: EvidenceKind,
    tier: Tier,
    chip_id: str,
    measurement: str,
    tcb: int,
    ssh_host_key: bytes | None = None,
) -> MockEvidence:
    """Build well-formed mock evidence: bound_report_data is computed for real."""

    bound = report_data(nonce, hotkey, ssh_host_key)
    return MockEvidence(
        kind=kind,
        tier=tier,
        chip_id=chip_id,
        measurement=measurement,
        tcb=tcb,
        miner_hotkey=hotkey,
        bound_report_data=bound,
        ssh_host_key=ssh_host_key,
    )


def mock_snp(
    nonce: bytes,
    hotkey: str,
    *,
    chip_id: str = "mock-snp-chip-0",
    measurement: str = "mock-snp-measurement-0",
    tcb: int = 1,
    ssh_host_key: bytes | None = None,
) -> MockEvidence:
    return mock_evidence(
        nonce,
        hotkey,
        kind=EvidenceKind.SEV_SNP,
        tier=Tier.CC_CPU_SNP,
        chip_id=chip_id,
        measurement=measurement,
        tcb=tcb,
        ssh_host_key=ssh_host_key,
    )


def mock_tdx(
    nonce: bytes,
    hotkey: str,
    *,
    chip_id: str = "mock-tdx-chip-0",
    measurement: str = "mock-tdx-measurement-0",
    tcb: int = 1,
    ssh_host_key: bytes | None = None,
) -> MockEvidence:
    return mock_evidence(
        nonce,
        hotkey,
        kind=EvidenceKind.TDX,
        tier=Tier.CC_CPU_TDX,
        chip_id=chip_id,
        measurement=measurement,
        tcb=tcb,
        ssh_host_key=ssh_host_key,
    )


def mock_gpu(
    nonce: bytes,
    hotkey: str,
    *,
    chip_id: str = "mock-gpu-chip-0",
    measurement: str = "mock-gpu-measurement-0",
    tcb: int = 1,
    ssh_host_key: bytes | None = None,
) -> MockEvidence:
    return mock_evidence(
        nonce,
        hotkey,
        kind=EvidenceKind.GPU_CC,
        tier=Tier.CC_GPU,
        chip_id=chip_id,
        measurement=measurement,
        tcb=tcb,
        ssh_host_key=ssh_host_key,
    )


def verify_mock(evidence: MockEvidence, nonce: bytes, policy: Policy) -> Attested | None:
    """MOCK verify: real binding + policy checks, no vendor crypto.

    Sybil dedup by chip_id is free but not done here — it lives at admission
    (validator / test), which keys the admitted-miner set by chip_id so one
    physical machine backs exactly one UID (docs/DESIGN.md §6).
    """

    expected = report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)
    if evidence.bound_report_data != expected:
        return None
    if evidence.measurement not in policy.allowed_measurements:
        return None
    if evidence.tcb < policy.min_tcb:
        return None
    return Attested(
        tier=evidence.tier,
        chip_id=evidence.chip_id,
        measurement=evidence.measurement,
        tcb=evidence.tcb,
    )
