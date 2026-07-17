"""Shared types: TEE tiers, attestation evidence, nonces, admission verdicts.

Pure-Python, dependency-free. The wire form lives in proto/evidence.proto; these
dataclasses are the in-process representation. See docs/DESIGN.md §3, §6.
"""

from __future__ import annotations

import enum
import hashlib
import os
import re
from dataclasses import dataclass, field


TDX_TCB_STATUSES = frozenset(
    {
        "UpToDate",
        "OutOfDate",
        "ConfigurationNeeded",
        "OutOfDateConfigurationNeeded",
        "SWHardeningNeeded",
        "ConfigurationAndSWHardeningNeeded",
        "Revoked",
    }
)
_TDX_POLICY_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class Tier(str, enum.Enum):
    """Confidential hardware classes admitted to the subnet (docs/DESIGN.md §3)."""

    CC_CPU_SNP = "cc_cpu_snp"   # AMD SEV-SNP, EPYC 7003 (Milan)+
    CC_CPU_TDX = "cc_cpu_tdx"   # Intel TDX, 5th-gen Xeon Scalable+
    CC_GPU = "cc_gpu"           # NVIDIA H100/H200/B200/B300 in CC mode


class EvidenceKind(str, enum.Enum):
    SEV_SNP = "sev_snp"
    TDX = "tdx"
    GPU_CC = "gpu_cc"


@dataclass(frozen=True)
class Evidence:
    """A miner's raw attestation evidence (mirrors proto/evidence.proto)."""

    kind: EvidenceKind
    quote: bytes
    nonce: bytes
    miner_hotkey: str
    cert_chain: list[bytes] = field(default_factory=list)
    ssh_host_key: bytes | None = None
    composite_jwt: str | None = None


@dataclass(frozen=True)
class Attested:
    """A verifier verdict. `chip_id` is the physical-machine identity used for

    free sybil defense — one machine backs exactly one UID (docs/DESIGN.md §6).
    """

    tier: Tier
    chip_id: str          # SNP CHIP_ID / TDX platform id / certified GPU UUID
    measurement: str      # the attested measurement, matched against policy
    tcb: int              # trusted computing base version
    verification_status: str = "VERIFIED"
    chain_verified: bool = True
    tcb_status: str | None = None
    advisory_ids: tuple[str, ...] = ()
    debug_enabled: bool | None = None
    collateral_current: bool | None = None
    platform_identity_kind: str | None = None
    tcb_svn: str | None = None
    pck_cert_id: str | None = None
    attestation_key_id: str | None = None
    policy_mode: str | None = None


def issue_nonce() -> bytes:
    """A fresh challenge nonce (validator side)."""

    return os.urandom(32)


def report_data(nonce: bytes, miner_hotkey: str, ssh_host_key: bytes | None = None) -> bytes:
    """The 64-byte REPORT_DATA bound into a quote.

    Binds freshness (nonce), identity (hotkey — defeats evidence relay), and,
    for Sandbox rentals, the SSH channel (host key). See docs/DESIGN.md §6, §7.
    """

    h = hashlib.sha512()
    h.update(nonce)
    h.update(miner_hotkey.encode())
    if ssh_host_key is not None:
        h.update(ssh_host_key)
    return h.digest()


@dataclass
class Policy:
    """Measurement policy the verifier enforces (docs/DESIGN.md §6)."""

    allowed_measurements: set[str] = field(default_factory=set)
    min_tcb: int = 0
    allowed_firmware: set[str] = field(default_factory=set)
    tdx_strict: bool = False
    tdx_allowed_tcb_statuses: set[str] = field(default_factory=lambda: {"UpToDate"})
    tdx_allowed_advisories: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not isinstance(self.tdx_strict, bool):
            raise ValueError("tdx_strict must be a boolean")
        for name, values in (
            ("tdx_allowed_tcb_statuses", self.tdx_allowed_tcb_statuses),
            ("tdx_allowed_advisories", self.tdx_allowed_advisories),
        ):
            if not isinstance(values, set) or any(
                not isinstance(value, str) or _TDX_POLICY_TOKEN.fullmatch(value) is None
                for value in values
            ):
                raise ValueError(f"{name} must be a set of bounded policy tokens")
        unknown = self.tdx_allowed_tcb_statuses - TDX_TCB_STATUSES
        if unknown:
            raise ValueError("tdx_allowed_tcb_statuses contains an unknown TCB status")
        if "Revoked" in self.tdx_allowed_tcb_statuses:
            raise ValueError("Revoked TDX platforms cannot be allowlisted")
        if self.tdx_strict and not self.tdx_allowed_tcb_statuses:
            raise ValueError("strict TDX policy requires at least one allowed TCB status")
