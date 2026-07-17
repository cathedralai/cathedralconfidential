"""Shared types: TEE tiers, attestation evidence, nonces, admission verdicts.

Pure-Python, dependency-free. The wire form lives in proto/evidence.proto; these
dataclasses are the in-process representation. See docs/DESIGN.md §3, §6.
"""

from __future__ import annotations

import enum
import hashlib
import os
import re
import struct
from dataclasses import dataclass, field

from cathedral.assurance import AssuranceClaims


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


class ChannelBindingType(str, enum.Enum):
    """Public-key identities supported by the v2 attestation binding."""

    TLS_SPKI_SHA256 = "tls_spki_sha256"
    APPLICATION_KEY_SHA256 = "application_key_sha256"


@dataclass(frozen=True)
class ChannelBinding:
    """A bounded digest of the key that must own the protected channel."""

    binding_type: ChannelBindingType
    digest: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.binding_type, ChannelBindingType):
            raise ValueError("channel binding type is unsupported")
        if not isinstance(self.digest, bytes) or len(self.digest) != 32:
            raise ValueError("channel binding digest must be exactly 32 bytes")

    def canonical_bytes(self) -> bytes:
        name = self.binding_type.value.encode("ascii")
        return b"cathedral.channel-binding\x00" + struct.pack(
            ">H", len(name)
        ) + name + self.digest


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
    report_data_version: int = 1
    channel_binding: ChannelBinding | None = None

    def __post_init__(self) -> None:
        if self.report_data_version not in {1, 2}:
            raise ValueError("unsupported report data version")
        if self.report_data_version == 1 and self.channel_binding is not None:
            raise ValueError("legacy report data cannot carry a v2 channel binding")
        if self.report_data_version == 2 and not isinstance(
            self.channel_binding, ChannelBinding
        ):
            raise ValueError("report data v2 requires a channel binding")


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
    assurance: AssuranceClaims | None = None


def issue_nonce() -> bytes:
    """A fresh challenge nonce (validator side)."""

    return os.urandom(32)


def report_data(nonce: bytes, miner_hotkey: str, ssh_host_key: bytes | None = None) -> bytes:
    """Legacy 64-byte REPORT_DATA retained for migration and test fixtures.

    Binds freshness (nonce), identity (hotkey), and the optional historical SSH
    host key. Production network admission uses :func:`report_data_v2`.
    """

    h = hashlib.sha512()
    h.update(nonce)
    h.update(miner_hotkey.encode())
    if ssh_host_key is not None:
        h.update(ssh_host_key)
    return h.digest()


_REPORT_DATA_V2_DOMAIN = b"cathedral.report-data\x00"
_REPORT_DATA_V2_VERSION = 2
_MAX_REPORT_HOTKEY_BYTES = 512


def _report_field(tag: int, value: bytes) -> bytes:
    if not 0 <= tag <= 255 or len(value) > 65535:
        raise ValueError("report data field is out of bounds")
    return bytes((tag,)) + struct.pack(">H", len(value)) + value


def report_data_v2(
    nonce: bytes,
    miner_hotkey: str,
    channel_binding: ChannelBinding,
) -> bytes:
    """Domain-separated, versioned, unambiguous 64-byte REPORT_DATA.

    Each variable-length field is tagged and length-delimited before SHA-512.
    The binding digest identifies either the live TLS SPKI or a separately
    negotiated application-encryption public key.
    """

    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise ValueError("report data v2 nonce must be exactly 32 bytes")
    if not isinstance(miner_hotkey, str):
        raise ValueError("report data v2 hotkey must be a string")
    try:
        hotkey = miner_hotkey.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("report data v2 hotkey must be valid UTF-8") from exc
    if not hotkey or len(hotkey) > _MAX_REPORT_HOTKEY_BYTES:
        raise ValueError("report data v2 hotkey is out of bounds")
    if not isinstance(channel_binding, ChannelBinding):
        raise ValueError("report data v2 requires a supported channel binding")

    payload = b"".join(
        (
            _REPORT_DATA_V2_DOMAIN,
            struct.pack(">H", _REPORT_DATA_V2_VERSION),
            _report_field(1, nonce),
            _report_field(2, hotkey),
            _report_field(3, channel_binding.binding_type.value.encode("ascii")),
            _report_field(4, channel_binding.digest),
        )
    )
    return hashlib.sha512(payload).digest()


def evidence_report_data(evidence: Evidence, nonce: bytes) -> bytes:
    """Compute the exact REPORT_DATA expected for an evidence envelope."""

    if evidence.report_data_version == 2:
        assert evidence.channel_binding is not None
        return report_data_v2(nonce, evidence.miner_hotkey, evidence.channel_binding)
    return report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)


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
