"""Shared types: TEE tiers, attestation evidence, nonces, admission verdicts.

Pure-Python, dependency-free. The wire form lives in proto/evidence.proto; these
dataclasses are the in-process representation. See docs/DESIGN.md §3, §6.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
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
_MAX_SQLITE_INTEGER = 2**63 - 1

# One shared evidence envelope contract keeps collectors, the worker, and the
# remote client on the same bounded wire limits.  Hex encoding doubles binary
# fields; the response bound includes two maximum-sized components plus fixed
# JSON/string overhead for each component.
MAX_EVIDENCE_COMPONENTS = 2
MAX_EVIDENCE_QUOTE_BYTES = 1 * 1024 * 1024
MAX_EVIDENCE_CERTIFICATES = 8
MAX_EVIDENCE_CERTIFICATE_BYTES = 256 * 1024
MAX_COMPOSITE_JWT_BYTES = 32 * 1024
MAX_EVIDENCE_COMPONENT_JSON_OVERHEAD = 64 * 1024
MAX_EVIDENCE_RESPONSE_BODY = MAX_EVIDENCE_COMPONENTS * (
    2 * MAX_EVIDENCE_QUOTE_BYTES
    + MAX_EVIDENCE_CERTIFICATES * 2 * MAX_EVIDENCE_CERTIFICATE_BYTES
    + MAX_COMPOSITE_JWT_BYTES
    + MAX_EVIDENCE_COMPONENT_JSON_OVERHEAD
)
# CPU-only responses retain the original small transport envelope. Composite
# responses are much larger, so validators reserve a conservative working set
# that covers the raw response plus decoded fields, or decoded evidence plus
# the verifier request strings, JSON text, and encoded subprocess payload.
MAX_CPU_EVIDENCE_RESPONSE_BODY = 128 * 1024
MAX_GPU_EVIDENCE_IN_FLIGHT_BYTES = 64 * 1024 * 1024


def _base64_encoded_bound(size: int) -> int:
    return 4 * ((size + 2) // 3)


MAX_GPU_EVIDENCE_DECODED_BYTES = MAX_EVIDENCE_COMPONENTS * (
    MAX_EVIDENCE_QUOTE_BYTES
    + MAX_EVIDENCE_CERTIFICATES * MAX_EVIDENCE_CERTIFICATE_BYTES
    + MAX_COMPOSITE_JWT_BYTES
)
MAX_GPU_VERIFIER_REQUEST_BYTES = (
    MAX_EVIDENCE_COMPONENTS
    * (
        _base64_encoded_bound(MAX_EVIDENCE_QUOTE_BYTES)
        + MAX_EVIDENCE_CERTIFICATES * _base64_encoded_bound(MAX_EVIDENCE_CERTIFICATE_BYTES)
    )
    + MAX_COMPOSITE_JWT_BYTES
    + MAX_EVIDENCE_COMPONENTS * MAX_EVIDENCE_COMPONENT_JSON_OVERHEAD
)
MAX_GPU_EVIDENCE_WORKING_SET_BYTES = max(
    2 * MAX_EVIDENCE_RESPONSE_BODY + MAX_GPU_EVIDENCE_DECODED_BYTES,
    MAX_GPU_EVIDENCE_DECODED_BYTES + 3 * MAX_GPU_VERIFIER_REQUEST_BYTES,
)
# Reserve another 8 MiB per admission for Python containers, subprocess pipe
# buffers, fixed protocol fields, and allocator overhead beyond the byte arrays
# counted above. The resulting reservation intentionally permits one maximum
# composite admission at a time under the 64 MiB validator-wide budget.
MAX_GPU_EVIDENCE_RESERVATION_BYTES = MAX_GPU_EVIDENCE_WORKING_SET_BYTES + 8 * 1024 * 1024
MAX_GPU_EVIDENCE_CONCURRENCY = (
    MAX_GPU_EVIDENCE_IN_FLIGHT_BYTES // MAX_GPU_EVIDENCE_RESERVATION_BYTES
)
if MAX_GPU_EVIDENCE_CONCURRENCY < 1:
    raise RuntimeError("GPU evidence contract exceeds its working-set budget")


_NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address embedded in an IPv6 transition address, else None.

    Covers IPv4-mapped (``::ffff:0:0/96``), 6to4 (``2002::/16``), and the NAT64
    well-known prefix (``64:ff9b::/96``). ``ipaddress.is_global`` looks only at
    the outer IPv6 prefix, so on its own it reports a transition address that
    wraps a private/loopback IPv4 as globally routable.
    """
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_globally_routable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Stricter ``ip.is_global`` that also rejects IPv6 transition addresses
    wrapping a non-global IPv4.

    ``ipaddress.is_global`` does not inspect the IPv4 embedded in NAT64/6to4/
    IPv4-mapped IPv6 addresses, so e.g. ``64:ff9b::7f00:1`` (127.0.0.1) reports
    ``is_global=True``. On a network with NAT64/DNS64 or 6to4 routing those
    resolve to the embedded IPv4 target, defeating an SSRF guard built on
    ``is_global`` alone. Require any embedded IPv4 to be global too.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not embedded.is_global:
            return False
    return ip.is_global


class Tier(str, enum.Enum):
    """Confidential hardware classes admitted to the subnet (docs/DESIGN.md §3)."""

    CC_CPU_SNP = "cc_cpu_snp"  # AMD SEV-SNP, EPYC 7003 (Milan)+
    CC_CPU_TDX = "cc_cpu_tdx"  # Intel TDX, 5th-gen Xeon Scalable+
    CC_GPU = "cc_gpu"  # NVIDIA H100/H200/B200/B300 in CC mode


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
        return b"cathedral.channel-binding\x00" + struct.pack(">H", len(name)) + name + self.digest


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
        if self.report_data_version == 2 and not isinstance(self.channel_binding, ChannelBinding):
            raise ValueError("report data v2 requires a channel binding")


@dataclass(frozen=True)
class Attested:
    """A verifier verdict. `chip_id` is the physical-machine identity used for

    free sybil defense — one machine backs exactly one UID (docs/DESIGN.md §6).
    """

    tier: Tier
    chip_id: str  # SNP CHIP_ID / TDX platform id / certified GPU UUID
    measurement: str  # the attested measurement, matched against policy
    tcb: int  # trusted computing base version
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


@dataclass(frozen=True)
class Policy:
    """Measurement policy the verifier enforces (docs/DESIGN.md §6)."""

    allowed_measurements: frozenset[str] = field(default_factory=frozenset)
    min_tcb: int = 0
    allowed_firmware: frozenset[str] = field(default_factory=frozenset)
    tdx_strict: bool = False
    tdx_allowed_tcb_statuses: frozenset[str] = field(
        default_factory=lambda: frozenset({"UpToDate"})
    )
    tdx_allowed_advisories: frozenset[str] = field(default_factory=frozenset)
    registry_release: int | None = None
    registry_digest: str | None = None
    registry_profile_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "allowed_measurements",
            "allowed_firmware",
            "tdx_allowed_tcb_statuses",
            "tdx_allowed_advisories",
        ):
            values = getattr(self, name)
            if not isinstance(values, (set, frozenset)):
                raise ValueError(f"{name} must be a set of bounded policy tokens")
            object.__setattr__(self, name, frozenset(values))
        if not isinstance(self.tdx_strict, bool):
            raise ValueError("tdx_strict must be a boolean")
        for name, values in (
            ("tdx_allowed_tcb_statuses", self.tdx_allowed_tcb_statuses),
            ("tdx_allowed_advisories", self.tdx_allowed_advisories),
        ):
            if any(
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
        if (self.registry_release is None) != (self.registry_digest is None):
            raise ValueError("registry release and digest must be supplied together")
        if self.registry_release is not None and (
            isinstance(self.registry_release, bool)
            or not isinstance(self.registry_release, int)
            or not 0 < self.registry_release <= _MAX_SQLITE_INTEGER
            or not isinstance(self.registry_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.registry_digest) is None
        ):
            raise ValueError("registry policy metadata is invalid")
        if (
            not isinstance(self.registry_profile_ids, tuple)
            or len(set(self.registry_profile_ids)) != len(self.registry_profile_ids)
            or any(
                not isinstance(profile_id, str) or not profile_id
                for profile_id in self.registry_profile_ids
            )
        ):
            raise ValueError("registry profile ids must be unique strings")
