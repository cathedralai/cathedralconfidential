"""Typed NVIDIA Confidential Containers / Trustee composite-verdict adapter.

The adapter is executable, bounded, and fail-closed.  The default configuration
remains ineligible for the live launch gate because the supported NVIDIA C++
runtime is dynamic (``libnvat.so`` plus system libraries), while Cathedral has
no active, signed artifact manifest that proves the complete loader and
dependency closure.  Trustee/NVAT output also must not be translated into
invented security claims: only the exact evidence and verifier booleans below
are accepted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.cc_gpu import CcGpuJobContext
from cathedral.common import ChannelBinding, Evidence, EvidenceKind
from cathedral.policy_registry import PolicyRegistryError, canonical_json
from cathedral.receipt import ReceiptError, parse_receipt_json
from cathedral.workload import ExternalSignatureVerifier, ExternalVerifierConfig


TRUSTEE_PREFLIGHT_SCHEMA = "cathedral_trustee_composite_preflight_v1"
TRUSTEE_VERIFY_SCHEMA = "cathedral_trustee_composite_verify_v1"
TRUSTEE_RESULT_SCHEMA = "cathedral_trustee_composite_result_v1"
TRUSTEE_BACKEND = "nvidia-confidential-containers-trustee"
TRUSTEE_RUNTIME_MANIFEST_SCHEMA = "cathedral_trustee_runtime_manifest_v1"
TRUSTEE_VERDICT_SCHEMA = "cathedral_trustee_composite_verdict_v1"
TRUSTEE_VERDICT_KEYS = frozenset(
    {
        "schema",
        "job_context_digest",
        "nonce_digest",
        "subject_hotkey",
        "channel_binding_digest",
        "profile_id",
        "profile_authority",
        "cpu_evidence_digest",
        "gpu_evidence_digest",
        "composite_bundle_digest",
        "gpu_identity_set_digest",
        "trustee_policy_digest",
        "runtime_manifest_digest",
        "verifier_digest",
        "same_guest_verified",
        "gpu_cc_mode_verified",
        "gpu_ready_state_verified",
        "measurement_policy_verified",
        "runtime_isolation_verified",
        "secret_release_authorized",
        "evidence_fresh",
        "runtime_ready",
    }
)
TRUSTEE_MANIFEST_SIGNATURE_DOMAIN = b"cathedral-trustee-runtime-manifest-v1\0"
TRUSTEE_PRODUCTION_BLOCKER = (
    "NOT PROVEN: no verified NVIDIA NVAT/Trustee runtime and dependency manifest "
    "is active for the exact composite-verdict contract"
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_QUOTE_BYTES = 2 * 1024 * 1024
_MAX_CERTIFICATES = 16
_MAX_CERTIFICATE_BYTES = 256 * 1024
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_VERDICT_ISSUER = object()


class TrusteeAdapterError(RuntimeError):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


class _Runner(Protocol):
    def _invoke(self, request: Mapping[str, object]) -> dict[str, object]: ...


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TrusteeAdapterError("schema", f"Trustee {label} is invalid")
    return value


def _evidence_document(evidence: Evidence, expected_kind: EvidenceKind) -> Mapping[str, object]:
    if (
        not isinstance(evidence, Evidence)
        or evidence.kind is not expected_kind
        or not isinstance(evidence.quote, bytes)
        or not 0 < len(evidence.quote) <= _MAX_QUOTE_BYTES
        or not isinstance(evidence.cert_chain, list)
        or len(evidence.cert_chain) > _MAX_CERTIFICATES
        or any(
            not isinstance(certificate, bytes)
            or not 0 < len(certificate) <= _MAX_CERTIFICATE_BYTES
            for certificate in evidence.cert_chain
        )
    ):
        raise TrusteeAdapterError("evidence", "Trustee evidence component is invalid")
    return MappingProxyType(
        {
            "cert_chain_b64": [
                base64.b64encode(certificate).decode("ascii")
                for certificate in evidence.cert_chain
            ],
            "composite_jwt": evidence.composite_jwt,
            "kind": evidence.kind.value,
            "quote_b64": base64.b64encode(evidence.quote).decode("ascii"),
        }
    )


def _manifest_unsigned(document: Mapping[str, object]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    try:
        return canonical_json(unsigned)
    except PolicyRegistryError as exc:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest is not canonical") from exc


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise TrusteeAdapterError("manifest", f"Trustee {label} is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TrusteeAdapterError("manifest", f"Trustee {label} is invalid") from exc


@dataclass(frozen=True)
class TrusteeRuntimeArtifact:
    path: str
    digest: str
    role: str


@dataclass(frozen=True)
class VerifiedTrusteeRuntimeManifest:
    release: int
    profile_id: str
    profile_authority: str
    trustee_policy_digest: str
    valid_from: datetime
    valid_until: datetime
    artifacts: tuple[TrusteeRuntimeArtifact, ...]
    signing_key_id: str
    digest: str
    canonical_document: bytes

    @property
    def executable_path(self) -> str:
        return next(item.path for item in self.artifacts if item.role == "executable")

    @property
    def executable_digest(self) -> str:
        return next(item.digest for item in self.artifacts if item.role == "executable")


def sign_trustee_runtime_manifest(
    document: Mapping[str, object],
    private_key_seed: bytes,
) -> dict[str, object]:
    """Sign a canonical runtime/dependency closure for operator publication."""

    if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
        raise TrusteeAdapterError("manifest", "Trustee manifest signing seed is invalid")
    if "signature" in document:
        raise TrusteeAdapterError("manifest", "Trustee manifest is already signed")
    signed = dict(document)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(
        TRUSTEE_MANIFEST_SIGNATURE_DOMAIN + _manifest_unsigned(signed)
    )
    signed["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def verify_trustee_runtime_manifest(
    data: bytes | str,
    trusted_signing_keys: Mapping[str, bytes],
    *,
    at: datetime,
    require_root_owned: bool = True,
) -> VerifiedTrusteeRuntimeManifest:
    """Verify signature, exact profile/policy metadata, and every local artifact."""

    if not isinstance(trusted_signing_keys, Mapping) or not trusted_signing_keys:
        raise TrusteeAdapterError("manifest", "Trustee manifest trust roots are unavailable")
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() != timedelta(0):
        raise TrusteeAdapterError("manifest", "Trustee manifest verification time is invalid")
    if not isinstance(require_root_owned, bool):
        raise TrusteeAdapterError("manifest", "Trustee manifest ownership policy is invalid")
    try:
        document = parse_receipt_json(data)
    except ReceiptError as exc:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest JSON is invalid") from exc
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    try:
        canonical_input = canonical_json(document)
    except PolicyRegistryError as exc:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest is not canonical") from exc
    expected_keys = {
        "artifacts",
        "dependency_closure_complete",
        "profile_authority",
        "profile_id",
        "release",
        "schema",
        "signature",
        "signing_key_id",
        "trustee_policy_digest",
        "valid_from",
        "valid_until",
    }
    if encoded != canonical_input or set(document) != expected_keys:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest schema is invalid")
    if (
        document["schema"] != TRUSTEE_RUNTIME_MANIFEST_SCHEMA
        or document["dependency_closure_complete"] is not True
        or document["profile_id"] != "gcp-a3-high-h100-tdx-v1"
        or not isinstance(document["profile_authority"], str)
        or not document["profile_authority"].startswith(
            f"gpu-profile:{document['profile_id']}@"
        )
    ):
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest policy is invalid")
    _require_digest(document["trustee_policy_digest"], "manifest policy digest")
    release = document["release"]
    if isinstance(release, bool) or not isinstance(release, int) or release <= 0:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest release is invalid")
    valid_from = _parse_time(document["valid_from"], "manifest valid_from")
    valid_until = _parse_time(document["valid_until"], "manifest valid_until")
    if not valid_from <= at < valid_until:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest is not currently valid")
    raw_artifacts = document["artifacts"]
    if not isinstance(raw_artifacts, list) or not 3 <= len(raw_artifacts) <= 64:
        raise TrusteeAdapterError("manifest", "Trustee runtime artifact closure is invalid")
    artifacts: list[TrusteeRuntimeArtifact] = []
    paths: set[str] = set()
    roles: list[str] = []
    for raw in raw_artifacts:
        if not isinstance(raw, dict) or set(raw) != {"digest", "path", "role"}:
            raise TrusteeAdapterError("manifest", "Trustee runtime artifact is invalid")
        path = raw["path"]
        role = raw["role"]
        digest = _require_digest(raw["digest"], "runtime artifact digest")
        if (
            not isinstance(path, str)
            or not os.path.isabs(path)
            or path in paths
            or not isinstance(role, str)
            or role not in {"executable", "loader", "dependency"}
        ):
            raise TrusteeAdapterError("manifest", "Trustee runtime artifact is invalid")
        paths.add(path)
        roles.append(role)
        artifacts.append(TrusteeRuntimeArtifact(path, digest, role))
    if roles.count("executable") != 1 or roles.count("loader") != 1 or "dependency" not in roles:
        raise TrusteeAdapterError("manifest", "Trustee runtime dependency closure is incomplete")
    for artifact in artifacts:
        try:
            path = Path(artifact.path)
            metadata = os.lstat(path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o022 != 0
                or (artifact.role == "executable" and metadata.st_mode & 0o111 == 0)
                or (require_root_owned and metadata.st_uid != 0)
            ):
                raise OSError
            if require_root_owned:
                for ancestor in path.parents:
                    ancestor_metadata = os.lstat(ancestor)
                    if (
                        ancestor_metadata.st_uid != 0
                        or ancestor_metadata.st_mode & 0o022 != 0
                    ):
                        raise OSError
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            hasher = hashlib.sha256()
            with os.fdopen(descriptor, "rb") as handle:
                opened = os.fstat(handle.fileno())
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
            after = os.lstat(path)
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
                or "sha256:" + hasher.hexdigest() != artifact.digest
            ):
                raise OSError
        except OSError as exc:
            raise TrusteeAdapterError(
                "manifest", "Trustee runtime artifact verification failed"
            ) from exc
    signature = document["signature"]
    key_id = document["signing_key_id"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "value_base64"}
        or signature["algorithm"] != "ed25519"
        or not isinstance(key_id, str)
        or key_id not in trusted_signing_keys
    ):
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest signature is invalid")
    public_key = trusted_signing_keys[key_id]
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest signature is invalid") from exc
    if (
        not isinstance(public_key, bytes)
        or len(public_key) != 32
        or len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii") != signature["value_base64"]
    ):
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest signature is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes,
            TRUSTEE_MANIFEST_SIGNATURE_DOMAIN + _manifest_unsigned(document),
        )
    except (InvalidSignature, ValueError) as exc:
        raise TrusteeAdapterError("manifest", "Trustee runtime manifest signature is invalid") from exc
    manifest_digest = "sha256:" + hashlib.sha256(_manifest_unsigned(document)).hexdigest()
    return VerifiedTrusteeRuntimeManifest(
        release=release,
        profile_id=document["profile_id"],
        profile_authority=document["profile_authority"],
        trustee_policy_digest=document["trustee_policy_digest"],
        valid_from=valid_from,
        valid_until=valid_until,
        artifacts=tuple(artifacts),
        signing_key_id=key_id,
        digest=manifest_digest,
        canonical_document=canonical_input,
    )


@dataclass(frozen=True, init=False)
class TrusteeCompositeVerdict:
    job_context_digest: str
    nonce_digest: str
    subject_hotkey: str
    channel_binding_digest: str
    profile_id: str
    profile_authority: str
    cpu_evidence_digest: str
    gpu_evidence_digest: str
    composite_bundle_digest: str
    gpu_identity_set_digest: str
    trustee_policy_digest: str
    runtime_manifest_digest: str
    verifier_digest: str
    same_guest_verified: bool
    gpu_cc_mode_verified: bool
    gpu_ready_state_verified: bool
    measurement_policy_verified: bool
    runtime_isolation_verified: bool
    secret_release_authorized: bool
    evidence_fresh: bool
    runtime_ready: bool
    canonical_document: bytes
    digest: str

    def __init__(
        self,
        *,
        job_context_digest: str,
        nonce_digest: str,
        subject_hotkey: str,
        channel_binding_digest: str,
        profile_id: str,
        profile_authority: str,
        cpu_evidence_digest: str,
        gpu_evidence_digest: str,
        composite_bundle_digest: str,
        gpu_identity_set_digest: str,
        trustee_policy_digest: str,
        runtime_manifest_digest: str,
        verifier_digest: str,
        same_guest_verified: bool,
        gpu_cc_mode_verified: bool,
        gpu_ready_state_verified: bool,
        measurement_policy_verified: bool,
        runtime_isolation_verified: bool,
        secret_release_authorized: bool,
        evidence_fresh: bool,
        runtime_ready: bool,
        _issuer: object,
    ) -> None:
        if _issuer is not _VERDICT_ISSUER:
            raise TrusteeAdapterError(
                "provenance", "Trustee verdicts may only be issued by the verified adapter"
            )
        values: dict[str, object] = {
            "schema": TRUSTEE_VERDICT_SCHEMA,
            "job_context_digest": job_context_digest,
            "nonce_digest": nonce_digest,
            "subject_hotkey": subject_hotkey,
            "channel_binding_digest": channel_binding_digest,
            "profile_id": profile_id,
            "profile_authority": profile_authority,
            "cpu_evidence_digest": cpu_evidence_digest,
            "gpu_evidence_digest": gpu_evidence_digest,
            "composite_bundle_digest": composite_bundle_digest,
            "gpu_identity_set_digest": gpu_identity_set_digest,
            "trustee_policy_digest": trustee_policy_digest,
            "runtime_manifest_digest": runtime_manifest_digest,
            "verifier_digest": verifier_digest,
            "same_guest_verified": same_guest_verified,
            "gpu_cc_mode_verified": gpu_cc_mode_verified,
            "gpu_ready_state_verified": gpu_ready_state_verified,
            "measurement_policy_verified": measurement_policy_verified,
            "runtime_isolation_verified": runtime_isolation_verified,
            "secret_release_authorized": secret_release_authorized,
            "evidence_fresh": evidence_fresh,
            "runtime_ready": runtime_ready,
        }
        assert set(values) == TRUSTEE_VERDICT_KEYS
        for name in (
            "job_context_digest",
            "nonce_digest",
            "channel_binding_digest",
            "cpu_evidence_digest",
            "gpu_evidence_digest",
            "composite_bundle_digest",
            "gpu_identity_set_digest",
            "trustee_policy_digest",
            "runtime_manifest_digest",
            "verifier_digest",
        ):
            _require_digest(values[name], name.replace("_", " "))
        canonical = canonical_json(values)
        for name, value in values.items():
            if name != "schema":
                object.__setattr__(self, name, value)
        object.__setattr__(self, "canonical_document", canonical)
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(canonical).hexdigest())

    @property
    def launch_eligible(self) -> bool:
        """Require pinned runtime readiness and every explicit verifier claim."""

        return bool(
            self.runtime_ready
            and self.same_guest_verified
            and self.gpu_cc_mode_verified
            and self.gpu_ready_state_verified
            and self.measurement_policy_verified
            and self.runtime_isolation_verified
            and self.secret_release_authorized
            and self.evidence_fresh
        )


class TrusteeCompositeAdapter:
    """Invoke a bounded local Trustee bridge and parse one exact composite verdict."""

    def __init__(
        self,
        config: ExternalVerifierConfig,
        *,
        profile_id: str,
        profile_authority: str,
        trustee_policy_digest: str,
        artifact_manifest_digest: str,
        runtime_manifest: VerifiedTrusteeRuntimeManifest | None = None,
        runner: _Runner | None = None,
    ) -> None:
        if not isinstance(config, ExternalVerifierConfig):
            raise TrusteeAdapterError("config", "Trustee adapter configuration is invalid")
        if profile_id != "gcp-a3-high-h100-tdx-v1":
            raise TrusteeAdapterError("policy", "Trustee CC-GPU profile is unsupported")
        if not isinstance(profile_authority, str) or not profile_authority.startswith(
            f"gpu-profile:{profile_id}@"
        ):
            raise TrusteeAdapterError("policy", "Trustee profile authority is invalid")
        self.profile_id = profile_id
        self.profile_authority = profile_authority
        self.trustee_policy_digest = _require_digest(
            trustee_policy_digest, "policy digest"
        )
        self.artifact_manifest_digest = _require_digest(
            artifact_manifest_digest, "artifact manifest digest"
        )
        if runtime_manifest is not None and not isinstance(
            runtime_manifest, VerifiedTrusteeRuntimeManifest
        ):
            raise TrusteeAdapterError("manifest", "verified Trustee runtime manifest is invalid")
        self._runtime_manifest_ready = bool(
            runtime_manifest is not None
            and runtime_manifest.digest == self.artifact_manifest_digest
            and runtime_manifest.profile_id == self.profile_id
            and runtime_manifest.profile_authority == self.profile_authority
            and runtime_manifest.trustee_policy_digest == self.trustee_policy_digest
            and runtime_manifest.executable_path == config.command[0]
        )
        self._runtime_verifier_digest = (
            runtime_manifest.executable_digest if runtime_manifest is not None else None
        )
        self._preflight_ready = False
        self._runner = runner or ExternalSignatureVerifier(config, working_directory="/")

    @property
    def production_ready(self) -> bool:
        return self._runtime_manifest_ready and self._preflight_ready

    @property
    def production_blocker(self) -> str:
        if not self._runtime_manifest_ready:
            return TRUSTEE_PRODUCTION_BLOCKER
        if not self._preflight_ready:
            return "NOT PROVEN: pinned Trustee runtime has not passed exact preflight"
        return ""

    def preflight(self) -> None:
        self._preflight_ready = False
        try:
            result = self._runner._invoke(
                {
                    "artifact_manifest_digest": self.artifact_manifest_digest,
                    "backend": TRUSTEE_BACKEND,
                    "operation": "preflight",
                    "profile_authority": self.profile_authority,
                    "profile_id": self.profile_id,
                    "schema": TRUSTEE_PREFLIGHT_SCHEMA,
                    "trustee_policy_digest": self.trustee_policy_digest,
                }
            )
        except Exception as exc:
            raise TrusteeAdapterError("unavailable", "Trustee preflight failed") from exc
        expected = {
            "artifact_manifest_digest": self.artifact_manifest_digest,
            "backend": TRUSTEE_BACKEND,
            "profile_authority": self.profile_authority,
            "profile_id": self.profile_id,
            "protocol_version": 1,
            "schema": TRUSTEE_PREFLIGHT_SCHEMA,
            "status": "ready",
            "trustee_policy_digest": self.trustee_policy_digest,
        }
        if result != expected:
            raise TrusteeAdapterError("unavailable", "Trustee preflight result is invalid")
        self._preflight_ready = True

    def verify(
        self,
        *,
        context: CcGpuJobContext,
        nonce: bytes,
        channel_binding: ChannelBinding,
        tdx_evidence: Evidence,
        gpu_evidence: Evidence,
    ) -> TrusteeCompositeVerdict:
        if not isinstance(context, CcGpuJobContext):
            raise TrusteeAdapterError("binding", "Trustee job context is invalid")
        if (
            context.profile_id != self.profile_id
            or context.profile_authority != self.profile_authority
        ):
            raise TrusteeAdapterError("binding", "Trustee job profile is mismatched")
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise TrusteeAdapterError("binding", "Trustee nonce must be exactly 32 bytes")
        if not isinstance(channel_binding, ChannelBinding):
            raise TrusteeAdapterError("binding", "Trustee channel binding is invalid")
        if (
            tdx_evidence.nonce != nonce
            or gpu_evidence.nonce != nonce
            or tdx_evidence.miner_hotkey != context.subject_hotkey
            or gpu_evidence.miner_hotkey != context.subject_hotkey
            or tdx_evidence.channel_binding != channel_binding
            or gpu_evidence.channel_binding != channel_binding
        ):
            raise TrusteeAdapterError("binding", "Trustee evidence envelope is mismatched")
        nonce_digest = "sha256:" + hashlib.sha256(nonce).hexdigest()
        channel_digest = "sha256:" + hashlib.sha256(
            channel_binding.canonical_bytes()
        ).hexdigest()
        request = {
            "artifact_manifest_digest": self.artifact_manifest_digest,
            "backend": TRUSTEE_BACKEND,
            "channel_binding_digest": channel_digest,
            "gpu_evidence": dict(_evidence_document(gpu_evidence, EvidenceKind.GPU_CC)),
            "job_context_digest": context.digest,
            "nonce_hex": nonce.hex(),
            "operation": "verify",
            "profile_authority": self.profile_authority,
            "profile_id": self.profile_id,
            "schema": TRUSTEE_VERIFY_SCHEMA,
            "subject_hotkey": context.subject_hotkey,
            "tdx_evidence": dict(_evidence_document(tdx_evidence, EvidenceKind.TDX)),
            "trustee_policy_digest": self.trustee_policy_digest,
        }
        try:
            result = self._runner._invoke(request)
        except Exception as exc:
            raise TrusteeAdapterError("unavailable", "Trustee verification failed") from exc
        expected_keys = {
            "backend",
            "channel_binding_digest",
            "composite_bundle_digest",
            "cpu_evidence_digest",
            "cpu_tee",
            "evidence_fresh",
            "gpu_evidence_digest",
            "gpu_identity_set_digest",
            "gpu_cc_mode_verified",
            "gpu_ready_state_verified",
            "gpu_tee",
            "job_context_digest",
            "measurement_policy_verified",
            "nonce_digest",
            "profile_authority",
            "profile_id",
            "runtime_isolation_verified",
            "runtime_manifest_digest",
            "same_guest_verified",
            "schema",
            "secret_release_authorized",
            "subject_hotkey",
            "trustee_policy_digest",
            "verifier_digest",
            "verdict",
        }
        if set(result) != expected_keys:
            raise TrusteeAdapterError("schema", "Trustee composite result schema is invalid")
        for name in (
            "channel_binding_digest",
            "composite_bundle_digest",
            "cpu_evidence_digest",
            "gpu_evidence_digest",
            "gpu_identity_set_digest",
            "job_context_digest",
            "nonce_digest",
            "runtime_manifest_digest",
            "trustee_policy_digest",
            "verifier_digest",
        ):
            _require_digest(result[name], name.replace("_", " "))
        if (
            result["schema"] != TRUSTEE_RESULT_SCHEMA
            or result["backend"] != TRUSTEE_BACKEND
            or result["verdict"] != "verified"
            or result["cpu_tee"] != "tdx"
            or result["gpu_tee"] != "nvidia_cc"
            or result["evidence_fresh"] is not True
            or result["same_guest_verified"] is not True
            or result["gpu_cc_mode_verified"] is not True
            or result["gpu_ready_state_verified"] is not True
            or result["measurement_policy_verified"] is not True
            or result["runtime_isolation_verified"] is not True
            or result["secret_release_authorized"] is not True
            or result["nonce_digest"] != nonce_digest
            or result["job_context_digest"] != context.digest
            or result["subject_hotkey"] != context.subject_hotkey
            or result["channel_binding_digest"] != channel_digest
            or result["profile_id"] != self.profile_id
            or result["profile_authority"] != self.profile_authority
            or result["trustee_policy_digest"] != self.trustee_policy_digest
            or result["runtime_manifest_digest"] != self.artifact_manifest_digest
            or (
                self._runtime_verifier_digest is not None
                and result["verifier_digest"] != self._runtime_verifier_digest
            )
        ):
            raise TrusteeAdapterError("denied", "Trustee composite evidence is not admissible")
        return TrusteeCompositeVerdict(
            job_context_digest=result["job_context_digest"],
            nonce_digest=result["nonce_digest"],
            subject_hotkey=result["subject_hotkey"],
            channel_binding_digest=result["channel_binding_digest"],
            profile_id=result["profile_id"],
            profile_authority=result["profile_authority"],
            cpu_evidence_digest=result["cpu_evidence_digest"],
            gpu_evidence_digest=result["gpu_evidence_digest"],
            composite_bundle_digest=result["composite_bundle_digest"],
            gpu_identity_set_digest=result["gpu_identity_set_digest"],
            trustee_policy_digest=result["trustee_policy_digest"],
            runtime_manifest_digest=result["runtime_manifest_digest"],
            verifier_digest=result["verifier_digest"],
            same_guest_verified=True,
            gpu_cc_mode_verified=True,
            gpu_ready_state_verified=True,
            measurement_policy_verified=True,
            runtime_isolation_verified=True,
            secret_release_authorized=True,
            evidence_fresh=True,
            runtime_ready=self.production_ready,
            _issuer=_VERDICT_ISSUER,
        )
