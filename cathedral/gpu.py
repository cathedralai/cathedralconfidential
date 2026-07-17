"""Fail-closed TDX plus NVIDIA confidential-GPU attestation.

Vendor cryptography remains in a pinned external verifier. Cathedral owns the
fresh challenge, strict result schema, exact profile policy, composite binding,
device-identity deduplication, and disabled-by-default score gate.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import shlex
import sqlite3
import stat
import struct
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from cathedral.assurance import (
    ATTESTATION_ADMISSION_POLICY,
    AssuranceClaims,
    ClaimStatus,
    evaluated_claim,
    not_evaluated_claim,
)
from cathedral.common import (
    Attested,
    ChannelBinding,
    Evidence,
    EvidenceKind,
    MAX_COMPOSITE_JWT_BYTES,
    MAX_EVIDENCE_CERTIFICATE_BYTES,
    MAX_EVIDENCE_CERTIFICATES,
    MAX_EVIDENCE_QUOTE_BYTES,
    Policy,
    Tier,
    report_data_v2,
)
from cathedral.lifecycle import canonical_utc
from cathedral.workload import ExternalSignatureVerifier, ExternalVerifierConfig


GPU_COLLECTION_SCHEMA = "cathedral_gpu_collection_v1"
GPU_VERIFIER_RESULT_SCHEMA = "cathedral_gpu_verifier_result_v1"
GPU_PREFLIGHT_SCHEMA = "cathedral_gpu_verifier_preflight_v1"
GPU_PROFILE_SCHEMA = "cathedral_gpu_profile_v1"
GPU_CHALLENGE_DOMAIN = b"cathedral-gpu-nonce-v1\0"
GPU_HOST_SESSION_DOMAIN = b"cathedral-gpu-host-session-v1\0"

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}")
_GPU_PROFILE_AUTHORITY_RE = re.compile(
    r"gpu-profile:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"@profile=sha256:[0-9a-f]{64}"
    r"(?:@release=none@registry=none|"
    r"@release=[1-9][0-9]{0,18}@registry=sha256:[0-9a-f]{64})"
)
_GPU_EVIDENCE_DENIAL_CATEGORIES = frozenset(
    {
        "composite_binding_denied",
        "cpu_component_denied",
        "gpu_component_denied",
        "gpu_policy_denied",
        "invalid_evidence",
    }
)
_MAX_DEVICES = 16
_MAX_PINNED_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_GPU_COLLECTOR_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_GPU_VERIFIER_INPUT_BYTES = 32 * 1024 * 1024
_GPU_REGISTRY_METADATA_KEYS = frozenset(
    {
        "allowed_cc_modes",
        "allowed_cpu_measurements",
        "allowed_drivers",
        "allowed_models",
        "allowed_security_states",
        "allowed_vbios",
        "cpu_kind",
        "expected_device_identity_digests",
        "verifier_digest",
    }
)
_GPU_WORKER_CLAIM = "worker_admission"
_GPU_CANARY_RESERVATION = "canary_reservation"
_GPU_CLAIM_KINDS = frozenset({_GPU_WORKER_CLAIM, _GPU_CANARY_RESERVATION})
_MAX_RECOVERY_REASON_LENGTH = 256
_MAX_IDENTITY_GENERATION = 2**63 - 1
_IDENTITY_ANCHOR_SLOT_BYTES = 256
_IDENTITY_ANCHOR_SLOTS = 2
_IDENTITY_ANCHOR_BYTES = _IDENTITY_ANCHOR_SLOT_BYTES * _IDENTITY_ANCHOR_SLOTS
_IDENTITY_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_IDENTITY_PROCESS_LOCKS_GUARD = threading.Lock()


def _identity_process_lock(path: Path) -> threading.RLock:
    key = str(path.resolve(strict=False))
    with _IDENTITY_PROCESS_LOCKS_GUARD:
        return _IDENTITY_PROCESS_LOCKS.setdefault(key, threading.RLock())


class GpuAttestationError(RuntimeError):
    """Stable, secret-safe GPU collection, verification, or policy failure."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def gpu_error_is_evidence_denial(exc: BaseException) -> bool:
    """Separate miner-controlled evidence denial from validator infrastructure."""

    return isinstance(exc, GpuAttestationError) and exc.category in (
        _GPU_EVIDENCE_DENIAL_CATEGORIES
    )


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _encoded_sha256(value: bytes) -> str:
    """Encode bytes that are already the output of SHA-256."""

    if not isinstance(value, bytes) or len(value) != hashlib.sha256().digest_size:
        raise GpuAttestationError("invalid_evidence", "SHA-256 value is invalid")
    return "sha256:" + value.hex()


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise GpuAttestationError("invalid_evidence", f"{name} is invalid")
    return value


def _require_token(value: object, name: str) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise GpuAttestationError("invalid_evidence", f"{name} is invalid")
    return value


def _canonical_gpu_uuid(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("GPU-"):
        raise GpuAttestationError("invalid_evidence", "GPU identity is invalid")
    try:
        parsed = uuid.UUID(value[4:])
    except (ValueError, AttributeError) as exc:
        raise GpuAttestationError("invalid_evidence", "GPU identity is invalid") from exc
    canonical = "GPU-" + str(parsed)
    if value != canonical:
        raise GpuAttestationError("invalid_evidence", "GPU identity is not canonical")
    return canonical


def gpu_identity_policy_digest(gpu_uuid: object) -> str:
    """Return the public, one-way identity used by signed GPU profiles."""

    canonical = _canonical_gpu_uuid(gpu_uuid)
    return _digest(b"cathedral-gpu-policy-identity-v1\0" + canonical.encode("ascii"))


def gpu_challenge(nonce: bytes, hotkey: str, binding: ChannelBinding) -> bytes:
    """Derive the independent GPU challenge from the complete v2 CPU binding."""

    return hashlib.sha256(GPU_CHALLENGE_DOMAIN + report_data_v2(nonce, hotkey, binding)).digest()


def gpu_host_session_digest(nonce: bytes, hotkey: str, binding: ChannelBinding) -> str:
    return _digest(GPU_HOST_SESSION_DOMAIN + report_data_v2(nonce, hotkey, binding))


def tdx_component_binding_digest(evidence: Evidence, verdict: Attested) -> str:
    """Digest the exact verified TDX component a GPU assertion must join.

    The digest covers the raw TDX envelope, its v2 challenge/channel binding,
    and the security-relevant claims produced by the independent TDX verifier.
    A pinned GPU verifier must validate vendor-backed composite evidence against
    this value and return it with ``composite_binding_verified=true``.
    """

    if (
        not isinstance(evidence, Evidence)
        or evidence.kind is not EvidenceKind.TDX
        or evidence.report_data_version != 2
        or evidence.channel_binding is None
        or not isinstance(evidence.quote, bytes)
        or not 0 < len(evidence.quote) <= MAX_EVIDENCE_QUOTE_BYTES
        or not isinstance(evidence.cert_chain, list)
        or len(evidence.cert_chain) > MAX_EVIDENCE_CERTIFICATES
        or evidence.ssh_host_key is not None
        or evidence.composite_jwt is not None
        or any(
            not isinstance(certificate, bytes)
            or not certificate
            or len(certificate) > MAX_EVIDENCE_CERTIFICATE_BYTES
            for certificate in evidence.cert_chain
        )
        or not isinstance(verdict, Attested)
        or verdict.tier is not Tier.CC_CPU_TDX
        or verdict.verification_status != "VERIFIED"
        or verdict.assurance is None
    ):
        raise GpuAttestationError("cpu_component_denied", "TDX component binding is invalid")
    try:
        report_binding = report_data_v2(
            evidence.nonce, evidence.miner_hotkey, evidence.channel_binding
        )
        verified_claims = _canonical_json(
            {
                "advisory_ids": list(verdict.advisory_ids),
                "attestation_key_id": verdict.attestation_key_id,
                "chip_id": verdict.chip_id,
                "collateral_current": verdict.collateral_current,
                "debug_enabled": verdict.debug_enabled,
                "hardware_evidence_digest": verdict.assurance.hardware.evidence_digest,
                "hardware_policy_digest": verdict.assurance.hardware.policy_digest,
                "measurement": verdict.measurement,
                "pck_cert_id": verdict.pck_cert_id,
                "platform_identity_kind": verdict.platform_identity_kind,
                "software_evidence_digest": verdict.assurance.software.evidence_digest,
                "software_policy_digest": verdict.assurance.software.policy_digest,
                "tcb": verdict.tcb,
                "tcb_status": verdict.tcb_status,
                "tcb_svn": verdict.tcb_svn,
                "verification_status": verdict.verification_status,
            }
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise GpuAttestationError(
            "cpu_component_denied", "TDX component binding is invalid"
        ) from exc
    digest = hashlib.sha256(b"cathedral-gpu-tdx-component-v1\0")
    values = (
        evidence.kind.value.encode("ascii"),
        evidence.quote,
        evidence.nonce,
        evidence.miner_hotkey.encode("utf-8"),
        evidence.report_data_version.to_bytes(2, "big"),
        evidence.channel_binding.canonical_bytes(),
        report_binding,
        evidence.ssh_host_key or b"",
        evidence.composite_jwt.encode("utf-8") if evidence.composite_jwt else b"",
        *evidence.cert_chain,
        verified_claims,
    )
    for value in values:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return "sha256:" + digest.hexdigest()


def _config_from_env(name: str) -> ExternalVerifierConfig:
    raw = os.environ.get(name)
    if not isinstance(raw, str) or not raw.strip():
        raise GpuAttestationError("unavailable", f"{name} is not configured")
    try:
        command = tuple(shlex.split(raw))
        artifacts_raw = os.environ.get(f"{name}_ARTIFACTS")
        artifacts: tuple[str, ...] = ()
        if artifacts_raw is not None:
            decoded = json.loads(artifacts_raw)
            if not isinstance(decoded, list) or any(not isinstance(item, str) for item in decoded):
                raise ValueError
            artifacts = tuple(decoded)
        return ExternalVerifierConfig(
            command,
            maximum_output_bytes=(
                MAX_GPU_COLLECTOR_OUTPUT_BYTES if name == "CATHEDRAL_GPU_COLLECT_CMD" else 64 * 1024
            ),
            maximum_input_bytes=(
                MAX_GPU_VERIFIER_INPUT_BYTES
                if name == "CATHEDRAL_GPU_VERIFY_CMD"
                else 16 * 1024 * 1024
            ),
            implementation_artifacts=artifacts,
        )
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise GpuAttestationError("unavailable", f"{name} is invalid") from exc


def _decode_b64(value: object, name: str, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise GpuAttestationError("invalid_evidence", f"{name} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise GpuAttestationError("invalid_evidence", f"{name} is invalid") from exc
    if not decoded or len(decoded) > maximum or base64.b64encode(decoded).decode() != value:
        raise GpuAttestationError("invalid_evidence", f"{name} is invalid")
    return decoded


def _validate_gpu_evidence(evidence: Evidence) -> None:
    if (
        not isinstance(evidence, Evidence)
        or evidence.kind is not EvidenceKind.GPU_CC
        or evidence.report_data_version != 2
        or evidence.channel_binding is None
        or not isinstance(evidence.quote, bytes)
        or not 0 < len(evidence.quote) <= MAX_EVIDENCE_QUOTE_BYTES
        or not isinstance(evidence.cert_chain, list)
        or len(evidence.cert_chain) > MAX_EVIDENCE_CERTIFICATES
        or any(
            not isinstance(certificate, bytes)
            or not certificate
            or len(certificate) > MAX_EVIDENCE_CERTIFICATE_BYTES
            for certificate in evidence.cert_chain
        )
        or (
            evidence.composite_jwt is not None
            and (
                not isinstance(evidence.composite_jwt, str)
                or not evidence.composite_jwt
                or not evidence.composite_jwt.isascii()
                or len(evidence.composite_jwt) > MAX_COMPOSITE_JWT_BYTES
                or any(ord(character) < 0x20 for character in evidence.composite_jwt)
            )
        )
    ):
        raise GpuAttestationError("gpu_component_denied", "GPU evidence is invalid")
    try:
        report_data_v2(evidence.nonce, evidence.miner_hotkey, evidence.channel_binding)
    except (TypeError, ValueError) as exc:
        raise GpuAttestationError(
            "gpu_component_denied", "GPU evidence binding is invalid"
        ) from exc


def _is_static_tdx_elf(artifact, size: int) -> bool:
    """Return whether *artifact* is a dependency-free x86-64 ELF executable."""

    try:
        artifact.seek(0)
        header = artifact.read(64)
        if len(header) != 64 or header[:4] != b"\x7fELF" or header[4:7] != b"\x02\x01\x01":
            return False
        elf_type, machine, version = struct.unpack_from("<HHI", header, 16)
        program_offset = struct.unpack_from("<Q", header, 32)[0]
        program_entry_size, program_count = struct.unpack_from("<HH", header, 54)
        if (
            elf_type not in {2, 3}
            or machine != 62
            or version != 1
            or program_count in {0, 0xFFFF}
            or program_entry_size < 56
            or program_count > 1024
            or program_offset > size
            or program_count * program_entry_size > size - program_offset
        ):
            return False
        has_load_segment = False
        for index in range(program_count):
            artifact.seek(program_offset + index * program_entry_size)
            program = artifact.read(56)
            if len(program) != 56:
                return False
            program_type = struct.unpack_from("<I", program, 0)[0]
            segment_offset = struct.unpack_from("<Q", program, 8)[0]
            segment_file_size = struct.unpack_from("<Q", program, 32)[0]
            if program_type == 1:
                has_load_segment = True
            if program_type == 3:
                return False
            if program_type != 2:
                continue
            if (
                segment_file_size > size
                or segment_offset > size
                or segment_file_size > size - segment_offset
                or segment_file_size % 16 != 0
            ):
                return False
            artifact.seek(segment_offset)
            found_terminator = False
            for _ in range(segment_file_size // 16):
                entry = artifact.read(16)
                if len(entry) != 16:
                    return False
                tag = struct.unpack_from("<Q", entry, 0)[0]
                if tag == 0:
                    found_terminator = True
                    break
                if tag == 1:
                    return False
            if not found_terminator:
                return False
        return has_load_segment
    except (OSError, struct.error, ValueError):
        return False


def _command_implementation_digest(
    config: ExternalVerifierConfig,
    *,
    require_static_elf: bool,
) -> str:
    """Hash a closed verifier argv plus its explicit implementation artifacts.

    Production GPU verification accepts a direct native executable with no
    argv extensions. Every artifact and path ancestor must be root-owned and
    non-writable by group or others. This closes pathname replacement and
    relative dependency discovery outside the signed artifact digest.
    """

    if len(config.command) != 1:
        raise GpuAttestationError(
            "verifier_config_invalid",
            "GPU verifier must be one direct native executable without arguments",
        )

    artifacts: list[str] = list(config.implementation_artifacts)
    if artifacts != [config.command[0]]:
        raise GpuAttestationError(
            "verifier_config_invalid",
            "GPU verifier must be one self-contained implementation artifact",
        )
    digest = hashlib.sha256()
    digest.update(b"cathedral-gpu-verifier-implementation-v1\0")
    digest.update(
        json.dumps(
            {
                "artifacts": artifacts,
                "argv": list(config.command),
                "environment": {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                "execution_format": (
                    "static-elf-x86_64" if require_static_elf else "development-native"
                ),
            },
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    for path in artifacts:
        try:
            resolved_path = os.path.realpath(path)
            for candidate in (Path(path), Path(resolved_path)):
                for ancestor in (candidate, *candidate.parents):
                    metadata = os.lstat(ancestor)
                    if metadata.st_uid != 0 or (
                        not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022 != 0
                    ):
                        raise OSError
            link_before = os.lstat(path)
            link_target = os.readlink(path) if stat.S_ISLNK(link_before.st_mode) else None
            artifact_path = resolved_path
            before = os.lstat(artifact_path)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0
                or before.st_mode & 0o022 != 0
            ):
                raise OSError
            if before.st_size > _MAX_PINNED_ARTIFACT_BYTES:
                raise OSError
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(artifact_path, flags)
            with os.fdopen(descriptor, "rb") as artifact:
                opened = os.fstat(artifact.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise OSError
                if path == config.command[0]:
                    header = artifact.read(4)
                    artifact.seek(0)
                    native_magics = {
                        b"\x7fELF",
                        b"\xfe\xed\xfa\xce",
                        b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf",
                        b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe",
                        b"\xbe\xba\xfe\xca",
                    }
                    if (
                        before.st_mode & 0o111 == 0
                        or (require_static_elf and not _is_static_tdx_elf(artifact, before.st_size))
                        or (
                            not require_static_elf
                            and header not in native_magics
                            and not header.startswith(b"MZ")
                        )
                    ):
                        raise OSError
                    artifact.seek(0)
                digest.update(len(path.encode("utf-8")).to_bytes(4, "big"))
                digest.update(path.encode("utf-8"))
                if link_target is not None:
                    digest.update(b"\0symlink\0")
                    digest.update(link_target.encode("utf-8"))
                while chunk := artifact.read(1024 * 1024):
                    digest.update(chunk)
            link_after = os.lstat(path)
            after = os.lstat(artifact_path)
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                or (
                    link_after.st_dev,
                    link_after.st_ino,
                    link_after.st_size,
                    link_after.st_mtime_ns,
                )
                != (
                    link_before.st_dev,
                    link_before.st_ino,
                    link_before.st_size,
                    link_before.st_mtime_ns,
                )
                or (link_target is not None and os.readlink(path) != link_target)
            ):
                raise OSError
        except (OSError, UnicodeEncodeError) as exc:
            raise GpuAttestationError(
                "verifier_config_invalid", "GPU verifier artifact pinning failed"
            ) from exc
    return "sha256:" + digest.hexdigest()


class ExternalGpuCollector:
    def __init__(self, config: ExternalVerifierConfig):
        if config.maximum_output_bytes != MAX_GPU_COLLECTOR_OUTPUT_BYTES:
            raise GpuAttestationError(
                "collector_config_invalid",
                "GPU collector output bound does not match the evidence contract",
            )
        self._runner = ExternalSignatureVerifier(config)

    def collect(
        self,
        nonce: bytes,
        hotkey: str,
        binding: ChannelBinding,
    ) -> Evidence:
        challenge = gpu_challenge(nonce, hotkey, binding)
        request = {
            "challenge_digest": _encoded_sha256(challenge),
            "operation": "collect",
            "schema": GPU_COLLECTION_SCHEMA,
        }
        try:
            result = self._runner._invoke(request)
        except Exception as exc:
            raise GpuAttestationError(
                "collector_unavailable", "GPU collector did not return evidence"
            ) from exc
        if (
            set(result)
            != {
                "cert_chain_b64",
                "composite_jwt",
                "quote_b64",
                "schema",
            }
            or result.get("schema") != GPU_COLLECTION_SCHEMA
        ):
            raise GpuAttestationError("invalid_evidence", "GPU collector result is invalid")
        quote = _decode_b64(result["quote_b64"], "GPU quote", MAX_EVIDENCE_QUOTE_BYTES)
        raw_chain = result["cert_chain_b64"]
        if not isinstance(raw_chain, list) or len(raw_chain) > MAX_EVIDENCE_CERTIFICATES:
            raise GpuAttestationError("invalid_evidence", "GPU certificate chain is invalid")
        chain = [
            _decode_b64(item, "GPU certificate", MAX_EVIDENCE_CERTIFICATE_BYTES)
            for item in raw_chain
        ]
        jwt = result["composite_jwt"]
        if jwt is not None and (
            not isinstance(jwt, str)
            or not jwt
            or not jwt.isascii()
            or len(jwt) > MAX_COMPOSITE_JWT_BYTES
            or any(ord(character) < 0x20 for character in jwt)
        ):
            raise GpuAttestationError("invalid_evidence", "composite JWT is invalid")
        return Evidence(
            kind=EvidenceKind.GPU_CC,
            quote=quote,
            cert_chain=chain,
            nonce=nonce,
            miner_hotkey=hotkey,
            composite_jwt=jwt,
            report_data_version=2,
            channel_binding=binding,
        )


@dataclass(frozen=True)
class GpuDeviceClaim:
    gpu_uuid: str
    model: str
    cc_mode: str
    driver: str
    vbios: str
    security_state: str
    evidence_verified: bool

    def __post_init__(self) -> None:
        _canonical_gpu_uuid(self.gpu_uuid)
        for name, value in (
            ("GPU model", self.model),
            ("GPU CC mode", self.cc_mode),
            ("GPU driver", self.driver),
            ("GPU VBIOS", self.vbios),
            ("GPU security state", self.security_state),
        ):
            _require_token(value, name)
        if not isinstance(self.evidence_verified, bool):
            raise GpuAttestationError("invalid_evidence", "GPU verification flag is invalid")

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "cc_mode": self.cc_mode,
                "driver": self.driver,
                "evidence_verified": self.evidence_verified,
                "gpu_uuid": self.gpu_uuid,
                "model": self.model,
                "security_state": self.security_state,
                "vbios": self.vbios,
            }
        )


@dataclass(frozen=True)
class GpuProfile:
    profile_id: str
    expected_device_identity_digests: frozenset[str]
    allowed_models: frozenset[str]
    allowed_cc_modes: frozenset[str]
    allowed_drivers: frozenset[str]
    allowed_vbios: frozenset[str]
    allowed_security_states: frozenset[str]
    allowed_cpu_measurements: frozenset[str]
    verifier_digest: str
    cpu_kind: EvidenceKind = EvidenceKind.TDX
    active: bool = False
    registry_release: int | None = None
    registry_digest: str | None = None
    registry_valid_from: datetime | None = field(default=None, init=False, repr=False)
    registry_valid_until: datetime | None = field(default=None, init=False, repr=False)
    _registry_verified: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_token(self.profile_id, "GPU profile id")
        if self.cpu_kind is not EvidenceKind.TDX:
            raise GpuAttestationError("invalid_policy", "first GPU profile requires Intel TDX")
        if not isinstance(self.active, bool):
            raise GpuAttestationError("invalid_policy", "GPU profile state is invalid")
        if (
            not isinstance(self.verifier_digest, str)
            or _DIGEST_RE.fullmatch(self.verifier_digest) is None
        ):
            raise GpuAttestationError("invalid_policy", "GPU verifier digest is invalid")
        if (self.registry_release is None) != (self.registry_digest is None):
            raise GpuAttestationError(
                "invalid_policy", "GPU registry release and digest must be paired"
            )
        if self.registry_release is not None and (
            isinstance(self.registry_release, bool)
            or not isinstance(self.registry_release, int)
            or self.registry_release <= 0
            or not isinstance(self.registry_digest, str)
            or _DIGEST_RE.fullmatch(self.registry_digest) is None
        ):
            raise GpuAttestationError("invalid_policy", "GPU registry binding is invalid")
        if (
            not isinstance(self.expected_device_identity_digests, frozenset)
            or not 1 <= len(self.expected_device_identity_digests) <= _MAX_DEVICES
            or any(
                not isinstance(item, str) or _DIGEST_RE.fullmatch(item) is None
                for item in self.expected_device_identity_digests
            )
        ):
            raise GpuAttestationError("invalid_policy", "GPU identity set is invalid")
        for name, values in (
            ("models", self.allowed_models),
            ("CC modes", self.allowed_cc_modes),
            ("drivers", self.allowed_drivers),
            ("VBIOS versions", self.allowed_vbios),
            ("security states", self.allowed_security_states),
            ("CPU measurements", self.allowed_cpu_measurements),
        ):
            if (
                not isinstance(values, frozenset)
                or not values
                or len(values) > 64
                or any(
                    not isinstance(item, str) or _TOKEN_RE.fullmatch(item) is None
                    for item in values
                )
            ):
                raise GpuAttestationError("invalid_policy", f"GPU profile {name} are invalid")

    @property
    def digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "active": self.active,
                    "allowed_cc_modes": sorted(self.allowed_cc_modes),
                    "allowed_cpu_measurements": sorted(self.allowed_cpu_measurements),
                    "allowed_drivers": sorted(self.allowed_drivers),
                    "allowed_models": sorted(self.allowed_models),
                    "allowed_security_states": sorted(self.allowed_security_states),
                    "allowed_vbios": sorted(self.allowed_vbios),
                    "cpu_kind": self.cpu_kind.value,
                    "expected_device_identity_digests": sorted(
                        self.expected_device_identity_digests
                    ),
                    "profile_id": self.profile_id,
                    "registry_digest": self.registry_digest,
                    "registry_release": self.registry_release,
                    "schema": GPU_PROFILE_SCHEMA,
                    "verifier_digest": self.verifier_digest,
                }
            )
        )

    @property
    def production_ready(self) -> bool:
        return self.production_ready_at(datetime.now(UTC))

    def production_ready_at(self, at: datetime) -> bool:
        """Return whether signed registry authority is still live at *at*."""

        return bool(
            self._registry_verified
            and self.active
            and self.registry_release is not None
            and isinstance(at, datetime)
            and at.tzinfo is not None
            and at.utcoffset() == timedelta(0)
            and isinstance(self.registry_valid_from, datetime)
            and isinstance(self.registry_valid_until, datetime)
            and self.registry_valid_from <= at < self.registry_valid_until
        )

    def production_ready_for(self, policy: Policy, *, at: datetime | None = None) -> bool:
        """Bind the live GPU profile to the same signed policy as its TDX half."""

        when = at or datetime.now(UTC)
        return bool(
            isinstance(policy, Policy)
            and self.production_ready_at(when)
            and policy.registry_release == self.registry_release
            and policy.registry_digest == self.registry_digest
        )


def gpu_profile_authority(profile: GpuProfile) -> str:
    """Return the exact profile authority used by scoring and ledger lineage."""

    if not isinstance(profile, GpuProfile):
        raise GpuAttestationError("invalid_policy", "GPU profile authority is invalid")
    if profile.registry_release is None:
        release = "none"
        registry_digest = "none"
    else:
        release = str(profile.registry_release)
        assert profile.registry_digest is not None
        registry_digest = profile.registry_digest
    authority = (
        f"gpu-profile:{profile.profile_id}@profile={profile.digest}"
        f"@release={release}@registry={registry_digest}"
    )
    if _GPU_PROFILE_AUTHORITY_RE.fullmatch(authority) is None:
        raise GpuAttestationError("invalid_policy", "GPU profile authority is invalid")
    return authority


def gpu_lifecycle_measurement(cpu_measurement: str, profile: GpuProfile) -> str:
    """Bind durable lifecycle policy to stable CPU and signed GPU authority."""

    _require_token(cpu_measurement, "CPU measurement")
    if cpu_measurement not in profile.allowed_cpu_measurements:
        raise GpuAttestationError("invalid_policy", "CPU measurement is outside the GPU profile")
    return _digest(
        b"cathedral-composite-gpu-lifecycle-measurement-v1\0"
        + cpu_measurement.encode("ascii")
        + b"\0"
        + gpu_profile_authority(profile).encode("ascii")
    )


def gpu_lifecycle_measurements(policy: Policy, profile: GpuProfile) -> frozenset[str]:
    """Return every stable composite measurement admitted by both authorities."""

    if not isinstance(policy, Policy) or not isinstance(profile, GpuProfile):
        raise GpuAttestationError("invalid_policy", "GPU lifecycle policy is invalid")
    return frozenset(
        gpu_lifecycle_measurement(measurement, profile)
        for measurement in policy.allowed_measurements
        if measurement in profile.allowed_cpu_measurements
    )


def gpu_profile_from_registry(
    snapshot: object,
    profile_id: str,
    *,
    at: datetime | None = None,
) -> GpuProfile:
    """Select one active GPU profile from a verified signed registry snapshot."""

    from cathedral.policy_registry import PolicyRegistrySnapshot

    if not isinstance(snapshot, PolicyRegistrySnapshot):
        raise GpuAttestationError("invalid_policy", "GPU registry snapshot is invalid")
    if not snapshot.signature_verified:
        raise GpuAttestationError(
            "invalid_policy", "GPU registry snapshot lacks verified signature provenance"
        )
    when = at or datetime.now(UTC)
    if not isinstance(when, datetime) or when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise GpuAttestationError("invalid_policy", "GPU policy time must be UTC")
    if not snapshot.valid_from <= when < snapshot.valid_until:
        raise GpuAttestationError("invalid_policy", "GPU registry is outside validity")
    selected = [
        profile
        for profile in snapshot.profiles
        if profile.profile_id == profile_id and profile.kind == "gpu_cc"
    ]
    if len(selected) != 1 or selected[0].status != "active" or not selected[0].eligible_at(when):
        raise GpuAttestationError("profile_inactive", "GPU profile is not active")
    profile = selected[0]
    metadata = profile.metadata
    if frozenset(metadata) != _GPU_REGISTRY_METADATA_KEYS:
        raise GpuAttestationError("invalid_policy", "GPU registry profile metadata is incomplete")
    if metadata["cpu_kind"] != EvidenceKind.TDX.value:
        raise GpuAttestationError("invalid_policy", "GPU profile requires Intel TDX")

    def string_set(name: str) -> frozenset[str]:
        raw = metadata[name]
        if not isinstance(raw, tuple) or len(raw) != len(set(raw)):
            raise GpuAttestationError("invalid_policy", f"GPU registry {name} is invalid")
        return frozenset(raw)

    selected_profile = GpuProfile(
        profile_id=profile.profile_id,
        expected_device_identity_digests=string_set("expected_device_identity_digests"),
        allowed_models=string_set("allowed_models"),
        allowed_cc_modes=string_set("allowed_cc_modes"),
        allowed_drivers=string_set("allowed_drivers"),
        allowed_vbios=string_set("allowed_vbios"),
        allowed_security_states=string_set("allowed_security_states"),
        allowed_cpu_measurements=string_set("allowed_cpu_measurements"),
        verifier_digest=metadata["verifier_digest"],
        active=True,
        registry_release=snapshot.release,
        registry_digest=snapshot.digest,
    )
    object.__setattr__(
        selected_profile, "registry_valid_from", max(snapshot.valid_from, profile.valid_from)
    )
    object.__setattr__(
        selected_profile, "registry_valid_until", min(snapshot.valid_until, profile.valid_until)
    )
    object.__setattr__(selected_profile, "_registry_verified", True)
    return selected_profile


@dataclass(frozen=True)
class GpuComponentVerdict:
    devices: tuple[GpuDeviceClaim, ...]
    evidence_digest: str
    challenge_digest: str
    host_session_digest: str
    profile_digest: str
    tdx_component_digest: str
    topology_digest: str | None

    @property
    def identity_set(self) -> frozenset[str]:
        return frozenset(device.gpu_uuid for device in self.devices)

    @property
    def digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "challenge_digest": self.challenge_digest,
                    "devices": [dict(device.document()) for device in self.devices],
                    "evidence_digest": self.evidence_digest,
                    "host_session_digest": self.host_session_digest,
                    "profile_digest": self.profile_digest,
                    "schema": GPU_VERIFIER_RESULT_SCHEMA,
                    "tdx_component_digest": self.tdx_component_digest,
                }
            )
        )

    def audit_dict(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "component": "gpu",
                "device_count": len(self.devices),
                "device_identity_digests": [
                    _digest(b"cathedral-gpu-public-id-v1\0" + item.encode())
                    for item in sorted(self.identity_set)
                ],
                "evidence_digest": self.evidence_digest,
                "profile_digest": self.profile_digest,
                "status": "verified",
                "tdx_component_digest": self.tdx_component_digest,
                "topology_digest": self.topology_digest,
            }
        )


class ExternalGpuVerifier:
    def __init__(
        self,
        config: ExternalVerifierConfig,
        *,
        production_mode: bool = True,
    ):
        if not isinstance(production_mode, bool):
            raise GpuAttestationError("verifier_config_invalid", "GPU verifier mode is invalid")
        implementation_digest = _command_implementation_digest(
            config,
            require_static_elf=production_mode,
        )
        object.__setattr__(
            self,
            "_runner",
            ExternalSignatureVerifier(config, working_directory="/"),
        )
        object.__setattr__(self, "_config", config)
        object.__setattr__(self, "_implementation_digest", implementation_digest)
        object.__setattr__(self, "_production_ready", production_mode)

    def __setattr__(self, name: str, value: object) -> None:
        if name in {
            "_runner",
            "_config",
            "_implementation_digest",
            "_production_ready",
        } and hasattr(self, name):
            raise AttributeError("GPU verifier configuration is immutable")
        object.__setattr__(self, name, value)

    @property
    def implementation_digest(self) -> str:
        return self._implementation_digest

    @property
    def production_ready(self) -> bool:
        return self._production_ready

    def _assert_pinned(self, profile: GpuProfile) -> None:
        current = _command_implementation_digest(
            self._config,
            require_static_elf=self._production_ready,
        )
        if current != self._implementation_digest or current != profile.verifier_digest:
            raise GpuAttestationError(
                "verifier_unavailable", "GPU verifier implementation is not pinned"
            )

    def preflight(self, profile: GpuProfile) -> None:
        self._assert_pinned(profile)
        try:
            result = self._runner._invoke(
                {
                    "operation": "preflight",
                    "profile_digest": profile.digest,
                    "schema": GPU_PREFLIGHT_SCHEMA,
                    "verifier_digest": profile.verifier_digest,
                }
            )
        except Exception as exc:
            raise GpuAttestationError(
                "verifier_unavailable", "GPU verifier preflight failed"
            ) from exc
        self._assert_pinned(profile)
        if result != {
            "profile_digest": profile.digest,
            "ready": True,
            "schema": GPU_PREFLIGHT_SCHEMA,
            "verifier_digest": profile.verifier_digest,
        }:
            raise GpuAttestationError("verifier_unavailable", "GPU verifier preflight failed")

    def verify(
        self,
        evidence: Evidence,
        profile: GpuProfile,
        *,
        tdx_evidence: Evidence,
        tdx_verdict: Attested,
    ) -> GpuComponentVerdict:
        _validate_gpu_evidence(evidence)
        tdx_digest = tdx_component_binding_digest(tdx_evidence, tdx_verdict)
        self.preflight(profile)
        assert evidence.channel_binding is not None
        challenge = _encoded_sha256(
            gpu_challenge(evidence.nonce, evidence.miner_hotkey, evidence.channel_binding)
        )
        host_session = gpu_host_session_digest(
            evidence.nonce, evidence.miner_hotkey, evidence.channel_binding
        )
        request = {
            "cert_chain_b64": [base64.b64encode(item).decode() for item in evidence.cert_chain],
            "challenge_digest": challenge,
            "composite_jwt": evidence.composite_jwt,
            "host_session_digest": host_session,
            "operation": "verify",
            "profile_digest": profile.digest,
            "quote_b64": base64.b64encode(evidence.quote).decode(),
            "schema": GPU_VERIFIER_RESULT_SCHEMA,
            "tdx_cert_chain_b64": [
                base64.b64encode(item).decode() for item in tdx_evidence.cert_chain
            ],
            "tdx_component_digest": tdx_digest,
            "tdx_measurement": tdx_verdict.measurement,
            "tdx_platform_id": tdx_verdict.chip_id,
            "tdx_quote_b64": base64.b64encode(tdx_evidence.quote).decode(),
            "tdx_tcb": tdx_verdict.tcb,
        }
        try:
            self._assert_pinned(profile)
            result = self._runner._invoke(request)
        except Exception as exc:
            raise GpuAttestationError(
                "verifier_unavailable", "GPU verifier did not return a verdict"
            ) from exc
        self._assert_pinned(profile)
        expected_keys = {
            "challenge_digest",
            "composite_binding_verified",
            "cpu_tee",
            "devices",
            "host_session_verified",
            "host_session_digest",
            "profile_digest",
            "schema",
            "topology_metadata",
            "tdx_component_digest",
            "tdx_measurement",
            "tdx_platform_id",
            "verifier_digest",
            "vendor_verified",
        }
        if (
            set(result) != expected_keys
            or result.get("schema") != GPU_VERIFIER_RESULT_SCHEMA
            or result.get("profile_digest") != profile.digest
            or result.get("verifier_digest") != profile.verifier_digest
            or not isinstance(result.get("cpu_tee"), str)
            or result.get("cpu_tee") not in {kind.value for kind in EvidenceKind}
            or not isinstance(result.get("tdx_measurement"), str)
            or _TOKEN_RE.fullmatch(result["tdx_measurement"]) is None
            or not isinstance(result.get("tdx_platform_id"), str)
            or _TOKEN_RE.fullmatch(result["tdx_platform_id"]) is None
            or any(
                not isinstance(result.get(field), str)
                or _DIGEST_RE.fullmatch(result[field]) is None
                for field in (
                    "challenge_digest",
                    "host_session_digest",
                    "tdx_component_digest",
                )
            )
            or any(
                not isinstance(result.get(field), bool)
                for field in (
                    "vendor_verified",
                    "host_session_verified",
                    "composite_binding_verified",
                )
            )
        ):
            raise GpuAttestationError(
                "verifier_unavailable", "GPU verifier protocol or authority mismatch"
            )
        if (
            result.get("vendor_verified") is not True
            or result.get("host_session_verified") is not True
            or result.get("composite_binding_verified") is not True
            or result.get("cpu_tee") != EvidenceKind.TDX.value
            or result.get("tdx_measurement") != tdx_verdict.measurement
            or result.get("tdx_platform_id") != tdx_verdict.chip_id
            or result.get("challenge_digest") != challenge
            or result.get("host_session_digest") != host_session
            or result.get("tdx_component_digest") != tdx_digest
        ):
            raise GpuAttestationError("gpu_component_denied", "GPU verifier binding failed")
        raw_devices = result["devices"]
        if not isinstance(raw_devices, list) or not 1 <= len(raw_devices) <= _MAX_DEVICES:
            raise GpuAttestationError("verifier_unavailable", "GPU verifier device list is invalid")
        devices: list[GpuDeviceClaim] = []
        for raw in raw_devices:
            if not isinstance(raw, dict) or set(raw) != {
                "cc_mode",
                "driver",
                "evidence_verified",
                "gpu_uuid",
                "model",
                "security_state",
                "vbios",
            }:
                raise GpuAttestationError(
                    "verifier_unavailable", "GPU verifier device claim is invalid"
                )
            try:
                devices.append(GpuDeviceClaim(**raw))
            except (GpuAttestationError, TypeError) as exc:
                raise GpuAttestationError(
                    "verifier_unavailable", "GPU verifier device claim is invalid"
                ) from exc
        devices.sort(key=lambda item: item.gpu_uuid)
        identities = [device.gpu_uuid for device in devices]
        if len(set(identities)) != len(identities):
            raise GpuAttestationError("verifier_unavailable", "duplicate GPU identity")
        if (
            frozenset(gpu_identity_policy_digest(item) for item in identities)
            != profile.expected_device_identity_digests
        ):
            raise GpuAttestationError("gpu_policy_denied", "GPU identity set does not match")
        for device in devices:
            if (
                device.evidence_verified is not True
                or device.model not in profile.allowed_models
                or device.cc_mode not in profile.allowed_cc_modes
                or device.driver not in profile.allowed_drivers
                or device.vbios not in profile.allowed_vbios
                or device.security_state not in profile.allowed_security_states
            ):
                raise GpuAttestationError("gpu_policy_denied", "GPU device policy failed")
        topology = result["topology_metadata"]
        if topology is not None and not isinstance(topology, (dict, list)):
            raise GpuAttestationError(
                "verifier_unavailable", "GPU verifier topology metadata is invalid"
            )
        try:
            topology_digest = (
                _digest(
                    json.dumps(
                        topology,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    ).encode("ascii")
                )
                if topology is not None
                else None
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise GpuAttestationError(
                "verifier_unavailable", "GPU verifier topology metadata is invalid"
            ) from exc
        evidence_digest = _digest(
            _canonical_json(
                {
                    "cert_chain_b64": request["cert_chain_b64"],
                    "composite_jwt": request["composite_jwt"],
                    "quote_b64": request["quote_b64"],
                    "schema": GPU_VERIFIER_RESULT_SCHEMA,
                }
            )
        )
        return GpuComponentVerdict(
            tuple(devices),
            evidence_digest,
            challenge,
            host_session,
            profile.digest,
            tdx_digest,
            topology_digest,
        )


@dataclass(frozen=True)
class PendingGpuIdentityClaim:
    """Opaque two-phase identity claim used only at the final admission boundary."""

    token: str = field(repr=False)
    hotkey_digest: str = field(repr=False)
    identity_digests: tuple[str, ...] = field(repr=False)
    bundle_digest: str
    claimed_at: str


class GpuIdentityRegistry:
    """Durable pseudonymous claims; one GPU cannot back two workers."""

    _EXPECTED_TABLE_COLUMNS = {
        "gpu_identity_registry_meta_v1": (
            ("singleton", "INTEGER", 0, None, 1),
            ("identity_key_check", "TEXT", 1, None, 0),
            ("claims_state_mac", "TEXT", 1, None, 0),
            ("database_generation", "INTEGER", 1, None, 0),
        ),
        "gpu_identity_claims_v3": (
            ("gpu_identity_digest", "TEXT", 0, None, 1),
            ("hotkey_digest", "TEXT", 1, None, 0),
            ("bundle_digest", "TEXT", 1, None, 0),
            ("claimed_at", "TEXT", 1, None, 0),
            ("claim_token", "TEXT", 0, None, 0),
            ("claim_kind", "TEXT", 1, None, 0),
        ),
        "gpu_identity_recovery_events_v1": (
            ("event_id", "TEXT", 0, None, 1),
            ("recovered_at", "TEXT", 1, None, 0),
            ("reason", "TEXT", 1, None, 0),
            ("worker_claims_committed", "INTEGER", 1, None, 0),
            ("worker_identities_committed", "INTEGER", 1, None, 0),
            ("canary_reservations_released", "INTEGER", 1, None, 0),
            ("canary_identities_released", "INTEGER", 1, None, 0),
            ("claim_token_digests_json", "TEXT", 1, None, 0),
        ),
    }

    @staticmethod
    def _keyed_digest(identity_digest_key: bytes, domain: bytes, value: str) -> str:
        return (
            "hmac-sha256:"
            + hmac.new(
                identity_digest_key,
                domain + value.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        )

    @classmethod
    def _prepare_claim_schema(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS gpu_identity_registry_meta_v1("
            "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
            "identity_key_check TEXT NOT NULL, claims_state_mac TEXT NOT NULL, "
            "database_generation INTEGER NOT NULL CHECK(database_generation>=0))"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS gpu_identity_claims_v3("
            "gpu_identity_digest TEXT PRIMARY KEY, hotkey_digest TEXT NOT NULL, "
            "bundle_digest TEXT NOT NULL, claimed_at TEXT NOT NULL, "
            "claim_token TEXT, claim_kind TEXT NOT NULL "
            "CHECK(claim_kind IN ('worker_admission','canary_reservation')))"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS gpu_identity_recovery_events_v1("
            "event_id TEXT PRIMARY KEY, recovered_at TEXT NOT NULL, "
            "reason TEXT NOT NULL, worker_claims_committed INTEGER NOT NULL, "
            "worker_identities_committed INTEGER NOT NULL, "
            "canary_reservations_released INTEGER NOT NULL, "
            "canary_identities_released INTEGER NOT NULL, "
            "claim_token_digests_json TEXT NOT NULL)"
        )
        if (
            connection.execute(
                "SELECT 1 FROM gpu_identity_claims_v3 "
                "WHERE claim_kind IS NULL OR claim_kind NOT IN (?,?) LIMIT 1",
                (_GPU_WORKER_CLAIM, _GPU_CANARY_RESERVATION),
            ).fetchone()
            is not None
        ):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity claim kind is invalid"
            )
        cls._validate_schema(connection)

    @classmethod
    def _schema_document(cls, connection: sqlite3.Connection) -> list[list[object]]:
        return [
            list(row)
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
            ).fetchall()
        ]

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection) -> None:
        objects = {
            (row[0], row[1])
            for row in connection.execute(
                "SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        expected_objects = {("table", table) for table in cls._EXPECTED_TABLE_COLUMNS}
        if objects != expected_objects:
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity registry schema or trigger set is invalid",
            )
        for table, expected in cls._EXPECTED_TABLE_COLUMNS.items():
            actual = tuple(
                (row[1], row[2].upper(), row[3], row[4], row[5])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            if actual != expected:
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity registry schema is invalid"
                )
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry integrity check failed"
            )

    def __init__(
        self,
        path: str | Path,
        *,
        identity_digest_key: bytes,
        production_mode: bool = False,
        generation_anchor_path: str | Path | None = None,
        initialize: bool | None = None,
    ):
        if not isinstance(path, (str, Path)) or not str(path) or str(path) == ":memory:":
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry must be durable"
            )
        if not isinstance(identity_digest_key, bytes) or len(identity_digest_key) < 32:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity digest key is invalid"
            )
        if not isinstance(production_mode, bool):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity production mode is invalid"
            )
        self.path = str(path)
        if generation_anchor_path is None:
            if production_mode:
                raise GpuAttestationError(
                    "identity_config_invalid",
                    "production GPU identity registry requires an external generation anchor",
                )
            generation_anchor_path = f"{self.path}.generation"
        if not isinstance(generation_anchor_path, (str, Path)) or not str(generation_anchor_path):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor path is invalid"
            )
        self._anchor_path = Path(generation_anchor_path)
        self._process_lock = _identity_process_lock(self._anchor_path)
        self._database_existed_at_start = Path(self.path).exists()
        self._anchor_existed_at_start = self._anchor_path.exists()
        if initialize is None:
            initialize = (
                not production_mode
                and not self._database_existed_at_start
                and not self._anchor_existed_at_start
            )
        if not isinstance(initialize, bool):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity initialization mode is invalid"
            )
        self._production_mode = production_mode
        self._identity_digest_key = bytes(identity_digest_key)
        self._expected_key_check = self._keyed_digest(
            self._identity_digest_key, b"cathedral-gpu-identity-key-check-v1\0", "registry"
        )
        self._parent_identity: tuple[int, int] | None = None
        self._anchor_parent_identity: tuple[int, int] | None = None
        self._database_identity: tuple[int, int] | None = None
        self._anchor_identity: tuple[int, int] | None = None
        if initialize and (self._database_existed_at_start or self._anchor_existed_at_start):
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity initialization requires unused database and anchor paths",
            )
        if not initialize and (
            not self._database_existed_at_start or not self._anchor_existed_at_start
        ):
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity database and generation anchor must already exist",
            )
        if self._production_mode:
            self._prepare_production_paths(initialize=initialize)
        if initialize:
            self._create_generation_anchor(0)
        with self._connect(authenticate=False) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prepare_claim_schema(connection)
            meta = connection.execute(
                "SELECT identity_key_check,claims_state_mac,database_generation "
                "FROM gpu_identity_registry_meta_v1 WHERE singleton=1"
            ).fetchone()
            if meta is None:
                if self._database_existed_at_start:
                    raise GpuAttestationError(
                        "identity_config_invalid",
                        "existing GPU identity registry lacks its authentication anchor",
                    )
                empty_mac = self._state_mac(connection, 0)
                connection.execute(
                    "INSERT INTO gpu_identity_registry_meta_v1 "
                    "(singleton,identity_key_check,claims_state_mac,database_generation) "
                    "VALUES (1,?,?,0)",
                    (self._expected_key_check, empty_mac),
                )
            elif not isinstance(meta[0], str) or not hmac.compare_digest(
                meta[0], self._expected_key_check
            ):
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity registry key mismatch"
                )
            if meta is not None:
                self._verify_authenticated_state(connection, meta)
            if (
                connection.execute(
                    "SELECT 1 FROM gpu_identity_claims_v3 WHERE claim_token IS NOT NULL LIMIT 1"
                ).fetchone()
                is not None
            ):
                raise GpuAttestationError(
                    "identity_recovery_required",
                    "GPU identity registry contains an interrupted admission",
                )
        if self._production_mode:
            self._parent_identity = self._validated_production_parent()
            self._anchor_parent_identity = self._validated_production_anchor_parent()
            self._database_identity = self._validated_production_identity()
            self._anchor_identity = self._validated_production_anchor_identity()

    @property
    def production_ready(self) -> bool:
        if not self._production_mode:
            return False
        with self._connect():
            pass
        return True

    def _prepare_production_paths(self, *, initialize: bool) -> None:
        database = Path(self.path)
        database_parent = self._validated_production_parent(require_stable=False)
        anchor_parent = self._validated_production_anchor_parent(require_stable=False)
        if database_parent == anchor_parent:
            raise GpuAttestationError(
                "identity_config_invalid",
                "production GPU identity anchor must use a separate protected directory",
            )
        if initialize:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(database, flags, 0o600)
                os.close(descriptor)
            except OSError as exc:
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity registry could not be created safely"
                ) from exc
        self._validated_production_identity(require_stable=False)
        if not initialize:
            self._validated_production_anchor_identity(require_stable=False)

    def _validated_production_anchor_parent(
        self, *, require_stable: bool = True
    ) -> tuple[int, int]:
        parent = self._anchor_path.parent
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity generation anchor parent is unavailable",
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity generation anchor parent must be owner-only and not a symlink",
            )
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            require_stable
            and self._anchor_parent_identity is not None
            and identity != self._anchor_parent_identity
        ):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor parent changed"
            )
        return identity

    def _validated_production_anchor_identity(
        self, *, require_stable: bool = True
    ) -> tuple[int, int]:
        self._validated_production_anchor_parent(require_stable=require_stable)
        try:
            metadata = self._anchor_path.lstat()
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is unavailable"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != _IDENTITY_ANCHOR_BYTES
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or (
                require_stable
                and self._anchor_identity is not None
                and identity != self._anchor_identity
            )
        ):
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity generation anchor ownership or identity changed",
            )
        return identity

    def _validated_production_parent(self, *, require_stable: bool = True) -> tuple[int, int]:
        parent = Path(self.path).parent
        try:
            parent_metadata = parent.lstat()
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry parent is unavailable"
            ) from exc
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or parent_metadata.st_mode & 0o077
        ):
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity registry parent must be owner-only and not a symlink",
            )
        identity = (parent_metadata.st_dev, parent_metadata.st_ino)
        if (
            require_stable
            and self._parent_identity is not None
            and identity != self._parent_identity
        ):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry parent changed"
            )
        return identity

    def _validated_production_identity(self, *, require_stable: bool = True) -> tuple[int, int]:
        self._validated_production_parent(require_stable=require_stable)
        try:
            metadata = Path(self.path).lstat()
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry is unavailable"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or (
                require_stable
                and self._database_identity is not None
                and identity != self._database_identity
            )
        ):
            raise GpuAttestationError(
                "identity_config_invalid",
                "GPU identity registry file ownership or identity changed",
            )
        return identity

    def _state_mac(self, connection: sqlite3.Connection, generation: int) -> str:
        claims = connection.execute(
            "SELECT gpu_identity_digest,hotkey_digest,bundle_digest,claimed_at,"
            "claim_token,claim_kind FROM gpu_identity_claims_v3 "
            "ORDER BY gpu_identity_digest"
        ).fetchall()
        recovery_events = connection.execute(
            "SELECT event_id,recovered_at,reason,worker_claims_committed,"
            "worker_identities_committed,canary_reservations_released,"
            "canary_identities_released,claim_token_digests_json "
            "FROM gpu_identity_recovery_events_v1 ORDER BY recovered_at,event_id"
        ).fetchall()
        document = json.dumps(
            {
                "claims": [list(row) for row in claims],
                "database_generation": generation,
                "recovery_events": [list(row) for row in recovery_events],
                "schema": self._schema_document(connection),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return (
            "hmac-sha256:"
            + hmac.new(
                self._identity_digest_key,
                b"cathedral-gpu-identity-state-v2\0" + document,
                hashlib.sha256,
            ).hexdigest()
        )

    def _generation_anchor_mac(self, generation: int) -> str:
        return (
            "hmac-sha256:"
            + hmac.new(
                self._identity_digest_key,
                b"cathedral-gpu-identity-generation-v1\0" + str(generation).encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
        )

    def _generation_anchor_line(self, generation: int) -> bytes:
        encoded = (
            json.dumps(
                {
                    "generation": generation,
                    "mac": self._generation_anchor_mac(generation),
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            + b"\n"
        )
        if len(encoded) > _IDENTITY_ANCHOR_SLOT_BYTES:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is invalid"
            )
        return encoded.ljust(_IDENTITY_ANCHOR_SLOT_BYTES, b"\0")

    def _create_generation_anchor(self, generation: int) -> None:
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(self._anchor_path, flags, 0o600)
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor could not be created"
            ) from exc
        try:
            encoded = self._generation_anchor_line(generation) + bytes(_IDENTITY_ANCHOR_SLOT_BYTES)
            if os.write(descriptor, encoded) != len(encoded):
                raise OSError("short generation anchor write")
            os.fsync(descriptor)
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor could not be stored"
            ) from exc
        finally:
            os.close(descriptor)

    def _read_generation_anchor(self) -> int:
        if self._production_mode:
            self._validated_production_anchor_identity()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._anchor_path, flags)
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is unavailable"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity generation anchor is invalid"
                )
            raw = os.read(descriptor, _IDENTITY_ANCHOR_BYTES + 1)
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is unavailable"
            ) from exc
        finally:
            os.close(descriptor)
        if len(raw) != _IDENTITY_ANCHOR_BYTES:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is invalid"
            )
        generations: list[int] = []
        for slot_index in range(_IDENTITY_ANCHOR_SLOTS):
            offset = slot_index * _IDENTITY_ANCHOR_SLOT_BYTES
            slot = raw[offset : offset + _IDENTITY_ANCHOR_SLOT_BYTES].rstrip(b"\0")
            if not slot:
                continue
            try:
                if not slot.endswith(b"\n"):
                    raise ValueError
                item = json.loads(slot.decode("ascii"))
                if not isinstance(item, dict) or set(item) != {"generation", "mac"}:
                    raise ValueError
                generation = item["generation"]
                if (
                    isinstance(generation, bool)
                    or not isinstance(generation, int)
                    or not 0 <= generation <= _MAX_IDENTITY_GENERATION
                    or generation % _IDENTITY_ANCHOR_SLOTS != slot_index
                    or not isinstance(item["mac"], str)
                    or not hmac.compare_digest(item["mac"], self._generation_anchor_mac(generation))
                ):
                    raise ValueError
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
                continue
            generations.append(generation)
        if not generations or (len(generations) == 2 and abs(generations[0] - generations[1]) != 1):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is invalid"
            )
        return max(generations)

    def _append_generation_anchor(self, previous: int, generation: int) -> None:
        if self._read_generation_anchor() != previous or generation != previous + 1:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity database generation changed"
            )
        flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._anchor_path, flags)
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is unavailable"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != _IDENTITY_ANCHOR_BYTES:
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity generation anchor is invalid"
                )
            encoded = self._generation_anchor_line(generation)
            offset = (generation % _IDENTITY_ANCHOR_SLOTS) * _IDENTITY_ANCHOR_SLOT_BYTES
            if os.pwrite(descriptor, encoded, offset) != len(encoded):
                raise OSError("short generation anchor write")
            os.fsync(descriptor)
        except OSError as exc:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor could not be stored"
            ) from exc
        finally:
            os.close(descriptor)

    def _verify_authenticated_state(self, connection: sqlite3.Connection, meta: object) -> int:
        self._validate_schema(connection)
        if not isinstance(meta, (tuple, sqlite3.Row)) or len(meta) != 3:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry authentication is invalid"
            )
        key_check, expected_mac, generation = meta
        if (
            not isinstance(key_check, str)
            or not hmac.compare_digest(key_check, self._expected_key_check)
            or not isinstance(expected_mac, str)
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 0 <= generation <= _MAX_IDENTITY_GENERATION
            or not hmac.compare_digest(expected_mac, self._state_mac(connection, generation))
        ):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry authenticated state changed"
            )
        anchor_generation = self._read_generation_anchor()
        if generation == anchor_generation + 1:
            # SQLite commits before the external anchor advances. A process
            # death in that narrow window leaves an authenticated database one
            # generation ahead, which is safe to reconcile while holding the
            # anchor lock. Larger gaps and anchor-ahead states remain failures.
            self._append_generation_anchor(anchor_generation, generation)
        elif generation != anchor_generation:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry authenticated state changed"
            )
        return generation

    def _commit_authenticated_state(
        self, connection: sqlite3.Connection, previous_generation: int
    ) -> None:
        self._validate_schema(connection)
        if previous_generation >= _MAX_IDENTITY_GENERATION:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity database generation is exhausted"
            )
        generation = previous_generation + 1
        cursor = connection.execute(
            "UPDATE gpu_identity_registry_meta_v1 "
            "SET claims_state_mac=?,database_generation=? "
            "WHERE singleton=1 AND database_generation=?",
            (self._state_mac(connection, generation), generation, previous_generation),
        )
        if cursor.rowcount != 1:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity database generation changed"
            )

    @contextmanager
    def _connect(self, *, authenticate: bool = True) -> Iterator[sqlite3.Connection]:
        with self._process_lock:
            if self._production_mode:
                self._validated_production_anchor_identity()
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                anchor_descriptor = os.open(self._anchor_path, flags)
            except OSError as exc:
                raise GpuAttestationError(
                    "identity_config_invalid",
                    "GPU identity generation anchor is unavailable",
                ) from exc
            try:
                fcntl.flock(anchor_descriptor, fcntl.LOCK_EX)
                anchor_metadata = os.fstat(anchor_descriptor)
                if (
                    not stat.S_ISREG(anchor_metadata.st_mode)
                    or anchor_metadata.st_size != _IDENTITY_ANCHOR_BYTES
                ):
                    raise GpuAttestationError(
                        "identity_config_invalid",
                        "GPU identity generation anchor is invalid",
                    )
                if self._production_mode:
                    anchor_identity = (
                        anchor_metadata.st_dev,
                        anchor_metadata.st_ino,
                    )
                    if (
                        self._anchor_identity is not None
                        and anchor_identity != self._anchor_identity
                    ):
                        raise GpuAttestationError(
                            "identity_config_invalid",
                            "GPU identity generation anchor changed",
                        )
                    self._validated_production_anchor_identity()
                    self._validated_production_identity()
                connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
                try:
                    if authenticate:
                        meta = connection.execute(
                            "SELECT identity_key_check,claims_state_mac,database_generation "
                            "FROM gpu_identity_registry_meta_v1 WHERE singleton=1"
                        ).fetchone()
                        self._verify_authenticated_state(connection, meta)
                    with connection:
                        yield connection
                    if authenticate:
                        # Reconcile only after SQLite has committed. The same
                        # process and inter-process locks remain held until the
                        # authenticated external high-water mark is durable.
                        meta = connection.execute(
                            "SELECT identity_key_check,claims_state_mac,database_generation "
                            "FROM gpu_identity_registry_meta_v1 WHERE singleton=1"
                        ).fetchone()
                        self._verify_authenticated_state(connection, meta)
                finally:
                    connection.close()
            finally:
                try:
                    fcntl.flock(anchor_descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(anchor_descriptor)

    def _begin_authenticated(self, connection: sqlite3.Connection, statement: str) -> int:
        connection.execute(statement)
        meta = connection.execute(
            "SELECT identity_key_check,claims_state_mac,database_generation "
            "FROM gpu_identity_registry_meta_v1 WHERE singleton=1"
        ).fetchone()
        return self._verify_authenticated_state(connection, meta)

    def _private_digest(self, domain: bytes, value: str) -> str:
        return self._keyed_digest(
            self._identity_digest_key,
            domain,
            value,
        )

    @classmethod
    def recover_interrupted(
        cls,
        path: str | Path,
        *,
        identity_digest_key: bytes,
        reason: str,
        production_mode: bool = False,
        generation_anchor_path: str | Path | None = None,
    ) -> Mapping[str, object]:
        """Reconcile crash-left claims using a deterministic fail-closed rule.

        Worker claims are conservatively committed because lifecycle admission
        may already have succeeded. Temporary canary reservations are released.
        The identity key authenticates the operation and every result is stored
        as a durable audit event before the transaction commits.
        """

        if (
            not isinstance(path, (str, Path))
            or not str(path)
            or str(path) == ":memory:"
            or not Path(path).is_file()
        ):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity registry does not exist"
            )
        if not isinstance(identity_digest_key, bytes) or len(identity_digest_key) < 32:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity digest key is invalid"
            )
        if (
            not isinstance(reason, str)
            or reason != reason.strip()
            or not 1 <= len(reason) <= _MAX_RECOVERY_REASON_LENGTH
            or any(ord(character) < 0x20 for character in reason)
        ):
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity recovery reason is invalid"
            )

        key = bytes(identity_digest_key)
        expected_key_check = cls._keyed_digest(
            key, b"cathedral-gpu-identity-key-check-v1\0", "registry"
        )
        guard = object.__new__(cls)
        guard.path = str(path)
        if generation_anchor_path is None:
            if production_mode:
                raise GpuAttestationError(
                    "identity_config_invalid",
                    "production GPU identity recovery requires its external generation anchor",
                )
            generation_anchor_path = f"{guard.path}.generation"
        guard._anchor_path = Path(generation_anchor_path)
        guard._process_lock = _identity_process_lock(guard._anchor_path)
        guard._database_existed_at_start = True
        guard._anchor_existed_at_start = guard._anchor_path.exists()
        guard._production_mode = production_mode
        guard._identity_digest_key = key
        guard._expected_key_check = expected_key_check
        guard._parent_identity = None
        guard._anchor_parent_identity = None
        guard._database_identity = None
        guard._anchor_identity = None
        if not guard._anchor_existed_at_start:
            raise GpuAttestationError(
                "identity_config_invalid", "GPU identity generation anchor is unavailable"
            )
        if production_mode:
            guard._prepare_production_paths(initialize=False)
            guard._parent_identity = guard._validated_production_parent()
            guard._anchor_parent_identity = guard._validated_production_anchor_parent()
            guard._database_identity = guard._validated_production_identity()
            guard._anchor_identity = guard._validated_production_anchor_identity()
        with guard._connect() as connection:
            database_generation = guard._begin_authenticated(connection, "BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT claim_token,claim_kind,COUNT(*) "
                "FROM gpu_identity_claims_v3 WHERE claim_token IS NOT NULL "
                "GROUP BY claim_token,claim_kind ORDER BY claim_token,claim_kind"
            ).fetchall()
            if not rows:
                raise GpuAttestationError(
                    "identity_recovery_not_required",
                    "GPU identity registry has no interrupted admission",
                )
            token_kinds: dict[str, str] = {}
            token_digests: list[str] = []
            worker_claims = 0
            worker_identities = 0
            canary_reservations = 0
            canary_identities = 0
            for token, claim_kind, count in rows:
                if (
                    not isinstance(token, str)
                    or not isinstance(claim_kind, str)
                    or claim_kind not in _GPU_CLAIM_KINDS
                    or token in token_kinds
                    or not isinstance(count, int)
                    or count < 1
                ):
                    raise GpuAttestationError(
                        "identity_config_invalid",
                        "GPU identity recovery state is invalid",
                    )
                token_kinds[token] = claim_kind
                token_digests.append(
                    cls._keyed_digest(key, b"cathedral-gpu-recovery-token-v1\0", token)
                )
                if claim_kind == _GPU_WORKER_CLAIM:
                    worker_claims += 1
                    worker_identities += count
                    cursor = connection.execute(
                        "UPDATE gpu_identity_claims_v3 SET claim_token=NULL "
                        "WHERE claim_token=? AND claim_kind=?",
                        (token, claim_kind),
                    )
                else:
                    canary_reservations += 1
                    canary_identities += count
                    cursor = connection.execute(
                        "DELETE FROM gpu_identity_claims_v3 WHERE claim_token=? AND claim_kind=?",
                        (token, claim_kind),
                    )
                if cursor.rowcount != count:
                    raise GpuAttestationError(
                        "identity_config_invalid", "GPU identity recovery mutation was incomplete"
                    )

            event_id = uuid.uuid4().hex
            recovered_at = canonical_utc(datetime.now(UTC))
            token_digests_json = json.dumps(
                sorted(token_digests), separators=(",", ":"), ensure_ascii=True
            )
            connection.execute(
                "INSERT INTO gpu_identity_recovery_events_v1("
                "event_id,recovered_at,reason,worker_claims_committed,"
                "worker_identities_committed,canary_reservations_released,"
                "canary_identities_released,claim_token_digests_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    recovered_at,
                    reason,
                    worker_claims,
                    worker_identities,
                    canary_reservations,
                    canary_identities,
                    token_digests_json,
                ),
            )
            if (
                connection.execute(
                    "SELECT 1 FROM gpu_identity_claims_v3 WHERE claim_token IS NOT NULL LIMIT 1"
                ).fetchone()
                is not None
            ):
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity recovery mutation was incomplete"
                )
            guard._commit_authenticated_state(connection, database_generation)
        return MappingProxyType(
            {
                "event_id": event_id,
                "recovered_at": recovered_at,
                "reason": reason,
                "worker_claims_committed": worker_claims,
                "worker_identities_committed": worker_identities,
                "canary_reservations_released": canary_reservations,
                "canary_identities_released": canary_identities,
                "claim_token_digests": tuple(sorted(token_digests)),
            }
        )

    def recovery_history(self) -> tuple[Mapping[str, object], ...]:
        with self._connect() as connection:
            self._begin_authenticated(connection, "BEGIN")
            rows = connection.execute(
                "SELECT event_id,recovered_at,reason,worker_claims_committed,"
                "worker_identities_committed,canary_reservations_released,"
                "canary_identities_released,claim_token_digests_json "
                "FROM gpu_identity_recovery_events_v1 ORDER BY recovered_at,event_id"
            ).fetchall()
        return tuple(
            MappingProxyType(
                {
                    "event_id": row[0],
                    "recovered_at": row[1],
                    "reason": row[2],
                    "worker_claims_committed": row[3],
                    "worker_identities_committed": row[4],
                    "canary_reservations_released": row[5],
                    "canary_identities_released": row[6],
                    "claim_token_digests": tuple(json.loads(row[7])),
                }
            )
            for row in rows
        )

    def _claim_material(
        self,
        hotkey: str,
        verdict: GpuComponentVerdict,
        at: datetime | None,
    ) -> tuple[str, tuple[str, ...], str]:
        if (
            not isinstance(hotkey, str)
            or not hotkey
            or not isinstance(verdict, GpuComponentVerdict)
        ):
            raise GpuAttestationError("identity_conflict", "GPU worker identity is invalid")
        occurred = canonical_utc(at or datetime.now(UTC))
        hotkey_digest = self._private_digest(b"cathedral-gpu-hotkey-v1\0", hotkey)
        identity_digests = tuple(
            self._private_digest(b"cathedral-gpu-identity-v1\0", gpu_uuid)
            for gpu_uuid in sorted(verdict.identity_set)
        )
        return hotkey_digest, identity_digests, occurred

    def assert_unclaimed(self, verdict: GpuComponentVerdict) -> None:
        """Read-only guard that keeps a canary off every enrolled GPU."""

        _hotkey_digest, identity_digests, _occurred = self._claim_material(
            "canary-read-only", verdict, None
        )
        with self._connect() as connection:
            self._begin_authenticated(connection, "BEGIN")
            for identity_digest in identity_digests:
                if (
                    connection.execute(
                        "SELECT 1 FROM gpu_identity_claims_v3 WHERE gpu_identity_digest=?",
                        (identity_digest,),
                    ).fetchone()
                    is not None
                ):
                    raise GpuAttestationError(
                        "identity_conflict", "canary GPU identity is already enrolled"
                    )

    def begin_exclusive_reservation(
        self,
        hotkey: str,
        verdict: GpuComponentVerdict,
        *,
        at: datetime | None = None,
    ) -> PendingGpuIdentityClaim:
        """Reserve a canary's GPUs for one epoch without creating ownership."""

        hotkey_digest, identity_digests, occurred = self._claim_material(hotkey, verdict, at)
        token = uuid.uuid4().hex
        with self._connect() as connection:
            database_generation = self._begin_authenticated(connection, "BEGIN IMMEDIATE")
            for identity_digest in identity_digests:
                if (
                    connection.execute(
                        "SELECT 1 FROM gpu_identity_claims_v3 WHERE gpu_identity_digest=?",
                        (identity_digest,),
                    ).fetchone()
                    is not None
                ):
                    raise GpuAttestationError(
                        "identity_conflict", "canary GPU identity is already enrolled"
                    )
            connection.executemany(
                "INSERT INTO gpu_identity_claims_v3("
                "gpu_identity_digest,hotkey_digest,bundle_digest,claimed_at,"
                "claim_token,claim_kind) VALUES (?,?,?,?,?,?)",
                (
                    (
                        identity_digest,
                        hotkey_digest,
                        verdict.digest,
                        occurred,
                        token,
                        _GPU_CANARY_RESERVATION,
                    )
                    for identity_digest in identity_digests
                ),
            )
            reserved = connection.execute(
                "SELECT gpu_identity_digest,hotkey_digest,bundle_digest,claimed_at,"
                "claim_token,claim_kind FROM gpu_identity_claims_v3 "
                "WHERE claim_token=? ORDER BY gpu_identity_digest",
                (token,),
            ).fetchall()
            if reserved != [
                (
                    identity_digest,
                    hotkey_digest,
                    verdict.digest,
                    occurred,
                    token,
                    _GPU_CANARY_RESERVATION,
                )
                for identity_digest in sorted(identity_digests)
            ]:
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity reservation was not stored exactly"
                )
            self._commit_authenticated_state(connection, database_generation)
        return PendingGpuIdentityClaim(
            token,
            hotkey_digest,
            identity_digests,
            verdict.digest,
            occurred,
        )

    def begin_claim(
        self,
        hotkey: str,
        verdict: GpuComponentVerdict,
        *,
        at: datetime | None = None,
    ) -> PendingGpuIdentityClaim:
        hotkey_digest, identity_digests, occurred = self._claim_material(hotkey, verdict, at)
        token = uuid.uuid4().hex
        with self._connect() as connection:
            database_generation = self._begin_authenticated(connection, "BEGIN IMMEDIATE")
            inserted: set[str] = set()
            for identity_digest in identity_digests:
                row = connection.execute(
                    "SELECT hotkey_digest,claim_token,claim_kind "
                    "FROM gpu_identity_claims_v3 WHERE gpu_identity_digest=?",
                    (identity_digest,),
                ).fetchone()
                if row is not None and row[0] != hotkey_digest:
                    raise GpuAttestationError(
                        "identity_conflict", "GPU identity already backs another worker"
                    )
                if row is not None and (row[1] is not None or row[2] != _GPU_WORKER_CLAIM):
                    raise GpuAttestationError(
                        "identity_recovery_required",
                        "GPU identity admission is already in progress",
                    )
                if row is None:
                    connection.execute(
                        "INSERT INTO gpu_identity_claims_v3("
                        "gpu_identity_digest,hotkey_digest,bundle_digest,claimed_at,"
                        "claim_token,claim_kind) VALUES (?,?,?,?,?,?)",
                        (
                            identity_digest,
                            hotkey_digest,
                            verdict.digest,
                            occurred,
                            token,
                            _GPU_WORKER_CLAIM,
                        ),
                    )
                    inserted.add(identity_digest)
            for identity_digest in identity_digests:
                row = connection.execute(
                    "SELECT hotkey_digest,bundle_digest,claimed_at,claim_token,claim_kind "
                    "FROM gpu_identity_claims_v3 WHERE gpu_identity_digest=?",
                    (identity_digest,),
                ).fetchone()
                if identity_digest in inserted:
                    expected = (
                        hotkey_digest,
                        verdict.digest,
                        occurred,
                        token,
                        _GPU_WORKER_CLAIM,
                    )
                else:
                    expected = None
                if (expected is not None and row != expected) or (
                    expected is None
                    and (row is None or row[0] != hotkey_digest or row[3] is not None)
                ):
                    raise GpuAttestationError(
                        "identity_config_invalid", "GPU identity claim was not stored exactly"
                    )
            self._commit_authenticated_state(connection, database_generation)
        return PendingGpuIdentityClaim(
            token,
            hotkey_digest,
            identity_digests,
            verdict.digest,
            occurred,
        )

    def commit_claim(self, pending: PendingGpuIdentityClaim) -> None:
        if not isinstance(pending, PendingGpuIdentityClaim):
            raise GpuAttestationError("identity_config_invalid", "GPU identity claim is invalid")
        with self._connect() as connection:
            database_generation = self._begin_authenticated(connection, "BEGIN IMMEDIATE")
            for identity_digest in pending.identity_digests:
                row = connection.execute(
                    "SELECT hotkey_digest,claim_token,claim_kind "
                    "FROM gpu_identity_claims_v3 "
                    "WHERE gpu_identity_digest=?",
                    (identity_digest,),
                ).fetchone()
                if row is not None and row[0] != pending.hotkey_digest:
                    raise GpuAttestationError(
                        "identity_conflict", "GPU identity claim changed during admission"
                    )
                if (
                    row is None
                    or row[1] not in {None, pending.token}
                    or row[2] != _GPU_WORKER_CLAIM
                ):
                    raise GpuAttestationError(
                        "identity_recovery_required",
                        "GPU identity claim changed during admission",
                    )
            for identity_digest in pending.identity_digests:
                cursor = connection.execute(
                    "UPDATE gpu_identity_claims_v3 SET bundle_digest=?,claimed_at=?,"
                    "claim_token=NULL WHERE gpu_identity_digest=? AND hotkey_digest=?",
                    (
                        pending.bundle_digest,
                        pending.claimed_at,
                        identity_digest,
                        pending.hotkey_digest,
                    ),
                )
                row = connection.execute(
                    "SELECT hotkey_digest,bundle_digest,claimed_at,claim_token,claim_kind "
                    "FROM gpu_identity_claims_v3 WHERE gpu_identity_digest=?",
                    (identity_digest,),
                ).fetchone()
                if cursor.rowcount != 1 or row != (
                    pending.hotkey_digest,
                    pending.bundle_digest,
                    pending.claimed_at,
                    None,
                    _GPU_WORKER_CLAIM,
                ):
                    raise GpuAttestationError(
                        "identity_config_invalid", "GPU identity claim commit was incomplete"
                    )
            self._commit_authenticated_state(connection, database_generation)

    def rollback_claim(self, pending: PendingGpuIdentityClaim) -> None:
        if not isinstance(pending, PendingGpuIdentityClaim):
            return
        with self._connect() as connection:
            database_generation = self._begin_authenticated(connection, "BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM gpu_identity_claims_v3 WHERE claim_token=? AND hotkey_digest=?",
                (pending.token, pending.hotkey_digest),
            )
            if (
                connection.execute(
                    "SELECT 1 FROM gpu_identity_claims_v3 "
                    "WHERE claim_token=? OR (claim_token IS NOT NULL AND hotkey_digest=?) LIMIT 1",
                    (pending.token, pending.hotkey_digest),
                ).fetchone()
                is not None
            ):
                raise GpuAttestationError(
                    "identity_config_invalid", "GPU identity claim rollback was incomplete"
                )
            self._commit_authenticated_state(connection, database_generation)

    def claim(
        self,
        hotkey: str,
        verdict: GpuComponentVerdict,
        *,
        at: datetime | None = None,
    ) -> None:
        """Atomically commit a standalone claim outside runtime admission."""

        pending = self.begin_claim(hotkey, verdict, at=at)
        try:
            self.commit_claim(pending)
        except BaseException:
            self.rollback_claim(pending)
            raise


@dataclass(frozen=True)
class CompositeGpuResult:
    attested: Attested
    cpu_audit: Mapping[str, object]
    gpu_audit: Mapping[str, object]
    gpu_component: GpuComponentVerdict = field(repr=False)


def verify_composite_gpu(
    cpu_evidence: Evidence,
    gpu_evidence: Evidence,
    nonce: bytes,
    cpu_policy: Policy,
    profile: GpuProfile,
    verifier: ExternalGpuVerifier,
) -> CompositeGpuResult:
    """Purely verify one TDX and one GPU component under one fresh binding.

    Durable identity is intentionally not mutated here. The runtime commits the
    returned component only after live-channel and lifecycle admission succeed.
    """

    if not profile.active:
        raise GpuAttestationError("profile_inactive", "GPU profile is inactive")
    registry_bound = profile.registry_release is not None
    if registry_bound and not profile.production_ready_for(cpu_policy):
        raise GpuAttestationError(
            "profile_inactive", "GPU profile authority is expired or mismatched"
        )
    if (
        cpu_evidence.kind is not EvidenceKind.TDX
        or gpu_evidence.kind is not EvidenceKind.GPU_CC
        or cpu_evidence.nonce != nonce
        or gpu_evidence.nonce != nonce
        or cpu_evidence.miner_hotkey != gpu_evidence.miner_hotkey
        or cpu_evidence.report_data_version != 2
        or gpu_evidence.report_data_version != 2
        or cpu_evidence.channel_binding is None
        or cpu_evidence.channel_binding != gpu_evidence.channel_binding
    ):
        raise GpuAttestationError("composite_binding_denied", "GPU components are not bound")
    from cathedral.verify import verify  # avoid verifier package import cycle

    cpu = verify(cpu_evidence, nonce, cpu_policy)
    if (
        cpu is None
        or cpu.tier is not Tier.CC_CPU_TDX
        or cpu.verification_status != "VERIFIED"
        or not ATTESTATION_ADMISSION_POLICY.allows(cpu.assurance)
        or cpu.measurement not in profile.allowed_cpu_measurements
    ):
        raise GpuAttestationError("cpu_component_denied", "TDX component is not approved")
    gpu = verifier.verify(
        gpu_evidence,
        profile,
        tdx_evidence=cpu_evidence,
        tdx_verdict=cpu,
    )
    identity_material = "\n".join(sorted(gpu.identity_set)).encode()
    chip_id = (
        "gpu-set-sha256:"
        + hashlib.sha256(
            b"cathedral-composite-gpu-identity-v1\0"
            + cpu.chip_id.encode()
            + b"\0"
            + identity_material
        ).hexdigest()
    )
    measurement = gpu_lifecycle_measurement(cpu.measurement, profile)
    assert cpu.assurance is not None
    hardware_material = _canonical_json(
        {
            "cpu_evidence_digest": cpu.assurance.hardware.evidence_digest,
            "gpu_component_digest": gpu.digest,
            "schema": GPU_VERIFIER_RESULT_SCHEMA,
        }
    )
    software_material = _canonical_json(
        {
            "cpu_evidence_digest": cpu.assurance.software.evidence_digest,
            "gpu_component_digest": gpu.digest,
            "schema": GPU_VERIFIER_RESULT_SCHEMA,
        }
    )
    composite_policy_digest = _digest(
        _canonical_json(
            {
                "cpu_hardware_policy_digest": cpu.assurance.hardware.policy_digest,
                "cpu_software_policy_digest": cpu.assurance.software.policy_digest,
                "gpu_profile_digest": profile.digest,
                "schema": GPU_PROFILE_SCHEMA,
            }
        )
    )
    when = canonical_utc(datetime.now(UTC))
    hardware = evaluated_claim(
        ClaimStatus.PASSED,
        hardware_material,
        composite_policy_digest,
        verified_at=when,
    )
    software = evaluated_claim(
        ClaimStatus.PASSED,
        software_material,
        composite_policy_digest,
        verified_at=when,
    )
    claims = AssuranceClaims(
        hardware=hardware,
        software=software,
        channel=not_evaluated_claim(),
        work=not_evaluated_claim(),
    )
    attested = Attested(
        tier=Tier.CC_GPU,
        chip_id=chip_id,
        measurement=measurement,
        tcb=cpu.tcb,
        policy_mode=gpu_profile_authority(profile),
        assurance=claims,
    )
    if registry_bound and not profile.production_ready_for(cpu_policy):
        raise GpuAttestationError(
            "profile_inactive", "GPU profile authority expired during verification"
        )
    return CompositeGpuResult(
        attested,
        MappingProxyType(
            {
                "component": "tdx",
                "evidence_digest": cpu.assurance.hardware.evidence_digest,
                "measurement_digest": _digest(cpu.measurement.encode()),
                "status": "verified",
            }
        ),
        gpu.audit_dict(),
        gpu,
    )


def collect_gpu_from_env(nonce: bytes, hotkey: str, binding: ChannelBinding) -> Evidence:
    return ExternalGpuCollector(_config_from_env("CATHEDRAL_GPU_COLLECT_CMD")).collect(
        nonce, hotkey, binding
    )


def gpu_verifier_from_env(*, production_mode: bool = True) -> ExternalGpuVerifier:
    return ExternalGpuVerifier(
        _config_from_env("CATHEDRAL_GPU_VERIFY_CMD"),
        production_mode=production_mode,
    )


def gpu_scoring_enabled() -> bool:
    return os.environ.get("CATHEDRAL_ENABLE_GPU_SCORING", "false").lower() == "true"


def gpu_score_eligible(
    attested: Attested,
    *,
    profile: GpuProfile | None = None,
    policy: Policy | None = None,
    at: datetime | None = None,
) -> bool:
    if not isinstance(attested, Attested) or attested.tier is not Tier.CC_GPU:
        return False
    if (
        not gpu_scoring_enabled()
        or not isinstance(attested.policy_mode, str)
        or not isinstance(profile, GpuProfile)
        or not isinstance(policy, Policy)
    ):
        return False
    if _GPU_PROFILE_AUTHORITY_RE.fullmatch(attested.policy_mode) is None:
        return False
    if attested.policy_mode != gpu_profile_authority(profile):
        return False
    if profile.registry_release is None:
        if not profile.active or policy.registry_release is not None:
            return False
    elif not profile.production_ready_for(policy, at=at):
        return False
    active = {
        item.strip()
        for item in os.environ.get("CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES", "").split(",")
        if item.strip()
    }
    return attested.policy_mode in active
