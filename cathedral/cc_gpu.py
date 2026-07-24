"""Fail-closed confidential-GPU job bindings and signed completion receipts.

This module is intentionally independent of the audit-only NVIDIA verifier.
It defines the control-plane values that vendor-authenticated admission and
completion evidence must bind.  It does not make GPU hardware available and it
does not turn hybrid/provider provenance into confidential-GPU evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.assurance import sha256_digest
from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistrySnapshot,
    canonical_json,
)
from cathedral.receipt import ReceiptError, parse_receipt_json


CC_GPU_JOB_RECEIPT_SCHEMA = "cathedral_cc_gpu_job_receipt_v1"
CC_GPU_EXECUTION_CLASS = "cc_gpu"
CC_GPU_COMPLETED_OUTCOME = "completed"
JOB_CONTEXT_DOMAIN = b"cathedral-cc-gpu-job-context-v1\0"
ADMISSION_NONCE_DOMAIN = b"cathedral-cc-gpu-admission-nonce-v1\0"
COMPLETION_NONCE_DOMAIN = b"cathedral-cc-gpu-completion-nonce-v1\0"
MAX_CC_GPU_RECEIPT_AGE_SECONDS = 300

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_PROFILE_AUTHORITY_RE = re.compile(
    r"gpu-profile:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
    r"@profile=sha256:[0-9a-f]{64}"
    r"@release=[1-9][0-9]{0,18}@registry=sha256:[0-9a-f]{64}"
)
_RECEIPT_ID_RE = re.compile(r"cc-gpu-receipt-sha256:[0-9a-f]{64}")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_TOP_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "execution_class",
        "profile_id",
        "provider",
        "machine_type",
        "zone",
        "cpu_tee",
        "gpu_model",
        "gpu_count",
        "provisioning_model",
        "worker_id",
        "subject_hotkey",
        "job_id",
        "attempt_id",
        "profile_authority",
        "job_context_digest",
        "admission_bundle_digest",
        "admission_nonce_digest",
        "admission_cpu_evidence_digest",
        "admission_gpu_evidence_digest",
        "admission_gpu_identity_set_digest",
        "completion_bundle_digest",
        "completion_nonce_digest",
        "completion_cpu_evidence_digest",
        "completion_gpu_evidence_digest",
        "completion_gpu_identity_set_digest",
        "channel_binding_digest",
        "image_digest",
        "policy_digest",
        "input_digest",
        "model_digest",
        "result_digest",
        "artifact_manifest_digest",
        "secret_release_grant_digest",
        "outcome",
        "deletion_confirmed",
        "deletion_evidence_digest",
        "policy_registry_release",
        "policy_registry_digest",
        "issued_at",
        "signing_key_id",
        "signature",
    }
)


@dataclass(frozen=True)
class CcGpuCapability:
    """Pre-launch public state; live availability requires a later proof-bound contract."""

    availability: str = "unavailable"
    launch_gate: str = "NOT PROVEN"
    customer_jobs: bool = False
    live_evidence_digest: str | None = None
    schema: str = "cathedral_cc_gpu_capability_v1"
    hardware_class: str = "confidential_gpu"
    execution_class: str = CC_GPU_EXECUTION_CLASS
    profile_id: str = "gcp-a3-high-h100-tdx-v1"

    def __post_init__(self) -> None:
        if (
            self.schema != "cathedral_cc_gpu_capability_v1"
            or self.hardware_class != "confidential_gpu"
            or self.execution_class != CC_GPU_EXECUTION_CLASS
            or self.profile_id != "gcp-a3-high-h100-tdx-v1"
        ):
            raise CcGpuReceiptError("schema", "CC-GPU capability identity is invalid")
        unavailable = (
            self.availability == "unavailable"
            and self.launch_gate == "NOT PROVEN"
            and self.customer_jobs is False
            and self.live_evidence_digest is None
        )
        # A bare digest is not evidence that a supported H100 job traversed the
        # live attestation, secret-release, receipt, and validator chain.  Keep
        # this core worker capability unavailable until a separate contract can
        # verify a signed terminal launch-proof package against pinned keys.
        if not unavailable:
            raise CcGpuReceiptError("policy", "CC-GPU capability state is inconsistent")

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "availability": self.availability,
                "customer_jobs": self.customer_jobs,
                "execution_class": self.execution_class,
                "hardware_class": self.hardware_class,
                "launch_gate": self.launch_gate,
                "live_evidence_digest": self.live_evidence_digest,
                "profile_id": self.profile_id,
                "schema": self.schema,
            }
        )

    @classmethod
    def from_document(cls, value: object) -> CcGpuCapability:
        if not isinstance(value, dict) or set(value) != set(cls().document()):
            raise CcGpuReceiptError("schema", "CC-GPU capability schema is invalid")
        try:
            return cls(**value)
        except TypeError as exc:
            raise CcGpuReceiptError("schema", "CC-GPU capability schema is invalid") from exc


class CcGpuReceiptError(ReceiptError):
    """Stable confidential-GPU receipt failure."""


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise CcGpuReceiptError("schema", f"{label} must be a canonical SHA-256 digest")
    return value


def _require_worker_id(value: object) -> str:
    if not isinstance(value, str) or _UUID_RE.fullmatch(value) is None:
        raise CcGpuReceiptError("schema", "CC-GPU worker id is invalid")
    return value


def _require_subject_hotkey(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CcGpuReceiptError("schema", "CC-GPU subject hotkey is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CcGpuReceiptError("schema", "CC-GPU subject hotkey is invalid") from exc
    if len(encoded) > 512 or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise CcGpuReceiptError("schema", "CC-GPU subject hotkey is invalid")
    return value


def _require_job_id(value: object) -> str:
    if not isinstance(value, str) or _UUID_RE.fullmatch(value) is None:
        raise CcGpuReceiptError("schema", "CC-GPU job id is invalid")
    return value


def _require_attempt_id(value: object) -> str:
    if not isinstance(value, str) or _UUID_RE.fullmatch(value) is None:
        raise CcGpuReceiptError("schema", "CC-GPU attempt id is invalid")
    return value


def _require_profile_authority(value: object) -> str:
    if not isinstance(value, str) or _PROFILE_AUTHORITY_RE.fullmatch(value) is None:
        raise CcGpuReceiptError("policy", "CC-GPU profile authority is invalid")
    return value


def _framed(*values: str) -> bytes:
    framed = bytearray()
    for value in values:
        try:
            encoded = value.encode("utf-8")
        except (AttributeError, UnicodeEncodeError) as exc:
            raise CcGpuReceiptError("schema", "CC-GPU binding text is invalid") from exc
        if not encoded or len(encoded) > 4096:
            raise CcGpuReceiptError("schema", "CC-GPU binding text is out of bounds")
        framed.extend(len(encoded).to_bytes(4, "big"))
        framed.extend(encoded)
    return bytes(framed)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_bytes(value: str, label: str) -> bytes:
    return bytes.fromhex(_require_digest(value, label).removeprefix("sha256:"))


def _canonical_time(value: datetime, label: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CcGpuReceiptError("schema", f"{label} must be UTC")
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise CcGpuReceiptError("schema", f"{label} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CcGpuReceiptError("schema", f"{label} must be canonical UTC time") from exc


def _unsigned_bytes(document: Mapping[str, object]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    try:
        return canonical_json(unsigned)
    except PolicyRegistryError as exc:
        raise CcGpuReceiptError("schema", "CC-GPU receipt is not canonical") from exc


def _id_material(document: Mapping[str, object]) -> bytes:
    material = dict(document)
    material.pop("receipt_id", None)
    material.pop("signature", None)
    try:
        return canonical_json(material)
    except PolicyRegistryError as exc:
        raise CcGpuReceiptError("schema", "CC-GPU receipt is not canonical") from exc


@dataclass(frozen=True)
class CcGpuJobContext:
    """Immutable values committed into one attempt's fresh evidence nonce."""

    worker_id: str
    subject_hotkey: str
    job_id: str
    attempt_id: str
    profile_id: str
    provider: str
    machine_type: str
    zone: str
    cpu_tee: str
    gpu_model: str
    gpu_count: int
    provisioning_model: str
    profile_authority: str
    image_digest: str
    policy_digest: str
    input_digest: str
    model_digest: str

    def __post_init__(self) -> None:
        _require_worker_id(self.worker_id)
        _require_subject_hotkey(self.subject_hotkey)
        _require_job_id(self.job_id)
        _require_attempt_id(self.attempt_id)
        if self.profile_id != "gcp-a3-high-h100-tdx-v1":
            raise CcGpuReceiptError("policy", "CC-GPU profile id is unsupported")
        if (
            self.provider != "gcp"
            or self.machine_type != "a3-highgpu-1g"
            or self.zone != "us-central1-a"
            or self.cpu_tee != "intel_tdx"
            or self.gpu_model != "nvidia_h100_80gb"
            or isinstance(self.gpu_count, bool)
            or self.gpu_count != 1
            or self.provisioning_model != "spot"
        ):
            raise CcGpuReceiptError("policy", "CC-GPU infrastructure profile is unsupported")
        _require_profile_authority(self.profile_authority)
        if not self.profile_authority.startswith(f"gpu-profile:{self.profile_id}@"):
            raise CcGpuReceiptError("policy", "CC-GPU profile authority does not match profile id")
        for label, value in (
            ("image digest", self.image_digest),
            ("policy digest", self.policy_digest),
            ("input digest", self.input_digest),
            ("model digest", self.model_digest),
        ):
            _require_digest(value, label)

    @property
    def digest(self) -> str:
        return _digest(
            JOB_CONTEXT_DOMAIN
            + _framed(
                self.worker_id,
                self.subject_hotkey,
                self.job_id,
                self.attempt_id,
                self.profile_id,
                self.provider,
                self.machine_type,
                self.zone,
                self.cpu_tee,
                self.gpu_model,
                str(self.gpu_count),
                self.provisioning_model,
                self.profile_authority,
                self.image_digest,
                self.policy_digest,
                self.input_digest,
                self.model_digest,
            )
        )

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "attempt_id": self.attempt_id,
                "image_digest": self.image_digest,
                "input_digest": self.input_digest,
                "job_context_digest": self.digest,
                "job_id": self.job_id,
                "model_digest": self.model_digest,
                "provider": self.provider,
                "machine_type": self.machine_type,
                "zone": self.zone,
                "cpu_tee": self.cpu_tee,
                "gpu_model": self.gpu_model,
                "gpu_count": self.gpu_count,
                "provisioning_model": self.provisioning_model,
                "policy_digest": self.policy_digest,
                "profile_id": self.profile_id,
                "profile_authority": self.profile_authority,
                "subject_hotkey": self.subject_hotkey,
                "worker_id": self.worker_id,
            }
        )


def derive_admission_nonce(random_challenge: bytes, context: CcGpuJobContext) -> bytes:
    """Derive the exact fresh nonce used for composite admission evidence."""

    if not isinstance(random_challenge, bytes) or len(random_challenge) != 32:
        raise CcGpuReceiptError("schema", "admission challenge must be exactly 32 bytes")
    if not isinstance(context, CcGpuJobContext):
        raise CcGpuReceiptError("schema", "CC-GPU job context is invalid")
    return hashlib.sha256(
        ADMISSION_NONCE_DOMAIN
        + random_challenge
        + _digest_bytes(context.digest, "job-context digest")
    ).digest()


def derive_completion_nonce(
    random_challenge: bytes,
    context: CcGpuJobContext,
    *,
    admission_bundle_digest: str,
    result_digest: str,
    artifact_manifest_digest: str,
) -> bytes:
    """Derive the exact fresh nonce used for completion evidence."""

    if not isinstance(random_challenge, bytes) or len(random_challenge) != 32:
        raise CcGpuReceiptError("schema", "completion challenge must be exactly 32 bytes")
    if not isinstance(context, CcGpuJobContext):
        raise CcGpuReceiptError("schema", "CC-GPU job context is invalid")
    return hashlib.sha256(
        COMPLETION_NONCE_DOMAIN
        + random_challenge
        + _digest_bytes(context.digest, "job-context digest")
        + _digest_bytes(admission_bundle_digest, "admission bundle digest")
        + _digest_bytes(result_digest, "result digest")
        + _digest_bytes(artifact_manifest_digest, "artifact manifest digest")
    ).digest()


@dataclass(frozen=True)
class CcGpuJobReceipt:
    receipt_id: str
    receipt_bytes: bytes
    receipt_digest: str
    document: Mapping[str, object]


class CcGpuReceiptReplayGuard:
    """Atomic in-process replay guard; durable validators must persist equivalents."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._receipt_ids: set[str] = set()
        self._worker_ids: set[str] = set()
        self._job_ids: set[str] = set()
        self._attempt_ids: set[str] = set()
        self._evidence: set[str] = set()

    def claim(self, document: Mapping[str, object]) -> None:
        receipt_id = document["receipt_id"]
        worker_id = document["worker_id"]
        job_id = document["job_id"]
        attempt_id = document["attempt_id"]
        evidence = {
            document["admission_bundle_digest"],
            document["admission_cpu_evidence_digest"],
            document["admission_gpu_evidence_digest"],
            document["completion_bundle_digest"],
            document["completion_cpu_evidence_digest"],
            document["completion_gpu_evidence_digest"],
            document["admission_nonce_digest"],
            document["completion_nonce_digest"],
            document["secret_release_grant_digest"],
            document["deletion_evidence_digest"],
        }
        assert isinstance(receipt_id, str)
        assert all(isinstance(value, str) for value in (worker_id, job_id, attempt_id))
        assert all(isinstance(value, str) for value in evidence)
        with self._lock:
            if receipt_id in self._receipt_ids:
                raise CcGpuReceiptError("replay", "CC-GPU receipt was already ingested")
            if (
                worker_id in self._worker_ids
                or job_id in self._job_ids
                or attempt_id in self._attempt_ids
            ):
                raise CcGpuReceiptError(
                    "duplicate", "CC-GPU worker, job, or attempt already has a receipt"
                )
            if self._evidence.intersection(evidence):
                raise CcGpuReceiptError("replay", "CC-GPU evidence was reused")
            self._receipt_ids.add(receipt_id)
            self._worker_ids.add(worker_id)
            self._job_ids.add(job_id)
            self._attempt_ids.add(attempt_id)
            self._evidence.update(evidence)
            self._evidence.update(evidence)


class CcGpuJobReceiptIssuer:
    """Issue only completed, deletion-confirmed CC-GPU receipts."""

    def __init__(
        self,
        registry: PolicyRegistrySnapshot,
        signing_key_id: str,
        private_key_seed: bytes,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not isinstance(registry, PolicyRegistrySnapshot) or not registry.signature_verified:
            raise CcGpuReceiptError("policy", "verified receipt policy registry is required")
        if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
            raise CcGpuReceiptError("key", "receipt private key seed must be 32 bytes")
        key = registry.receipt_key(signing_key_id)
        if key is None:
            raise CcGpuReceiptError("key", "receipt signing key is absent from the registry")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if public_key != key.public_key:
            raise CcGpuReceiptError("key", "receipt private key does not match the registry")
        if not callable(clock):
            raise CcGpuReceiptError("schema", "receipt clock must be callable")
        self.registry = registry
        self.signing_key_id = signing_key_id
        self._private_key = private_key
        self._clock = clock

    def issue(
        self,
        *,
        context: CcGpuJobContext,
        admission_bundle_digest: str,
        admission_nonce_digest: str,
        admission_cpu_evidence_digest: str,
        admission_gpu_evidence_digest: str,
        admission_gpu_identity_set_digest: str,
        completion_bundle_digest: str,
        completion_nonce_digest: str,
        completion_cpu_evidence_digest: str,
        completion_gpu_evidence_digest: str,
        completion_gpu_identity_set_digest: str,
        channel_binding_digest: str,
        result_digest: str,
        artifact_manifest_digest: str,
        secret_release_grant_digest: str,
        deletion_evidence_digest: str,
        outcome: str = CC_GPU_COMPLETED_OUTCOME,
        deletion_confirmed: bool = True,
        issued_at: datetime | None = None,
    ) -> CcGpuJobReceipt:
        if not isinstance(context, CcGpuJobContext):
            raise CcGpuReceiptError("schema", "CC-GPU job context is invalid")
        when = issued_at if issued_at is not None else self._clock()
        when_text = _canonical_time(when, "receipt issue time")
        key = self.registry.receipt_key(self.signing_key_id)
        assert key is not None
        if not key.can_sign_at(when):
            raise CcGpuReceiptError("key", "receipt signing key is not active")
        if not self.registry.valid_from <= when < self.registry.valid_until:
            raise CcGpuReceiptError("policy", "receipt time is outside registry validity")
        digests = {
            label: _require_digest(value, label)
            for label, value in (
                ("admission bundle digest", admission_bundle_digest),
                ("admission nonce digest", admission_nonce_digest),
                ("admission CPU evidence digest", admission_cpu_evidence_digest),
                ("admission GPU evidence digest", admission_gpu_evidence_digest),
                ("admission GPU identity-set digest", admission_gpu_identity_set_digest),
                ("completion bundle digest", completion_bundle_digest),
                ("completion nonce digest", completion_nonce_digest),
                ("completion CPU evidence digest", completion_cpu_evidence_digest),
                ("completion GPU evidence digest", completion_gpu_evidence_digest),
                ("completion GPU identity-set digest", completion_gpu_identity_set_digest),
                ("channel binding digest", channel_binding_digest),
                ("result digest", result_digest),
                ("artifact manifest digest", artifact_manifest_digest),
                ("secret-release grant digest", secret_release_grant_digest),
                ("deletion evidence digest", deletion_evidence_digest),
            )
        }
        evidence_values = {
            admission_bundle_digest,
            admission_cpu_evidence_digest,
            admission_gpu_evidence_digest,
            completion_bundle_digest,
            completion_cpu_evidence_digest,
            completion_gpu_evidence_digest,
        }
        if len(evidence_values) != 6:
            raise CcGpuReceiptError("replay", "admission and completion evidence must be unique")
        if admission_nonce_digest == completion_nonce_digest:
            raise CcGpuReceiptError("replay", "admission and completion nonces must be unique")
        if admission_gpu_identity_set_digest != completion_gpu_identity_set_digest:
            raise CcGpuReceiptError(
                "binding", "admission and completion GPU identity sets must match"
            )
        if outcome != CC_GPU_COMPLETED_OUTCOME:
            raise CcGpuReceiptError("outcome", "CC-GPU reward receipt requires completed outcome")
        if deletion_confirmed is not True:
            raise CcGpuReceiptError("deletion", "CC-GPU receipt requires confirmed deletion")
        document: dict[str, object] = {
            "schema": CC_GPU_JOB_RECEIPT_SCHEMA,
            "execution_class": CC_GPU_EXECUTION_CLASS,
            **context.document(),
            "admission_bundle_digest": digests["admission bundle digest"],
            "admission_nonce_digest": digests["admission nonce digest"],
            "admission_cpu_evidence_digest": digests["admission CPU evidence digest"],
            "admission_gpu_evidence_digest": digests["admission GPU evidence digest"],
            "admission_gpu_identity_set_digest": digests[
                "admission GPU identity-set digest"
            ],
            "completion_bundle_digest": digests["completion bundle digest"],
            "completion_nonce_digest": digests["completion nonce digest"],
            "completion_cpu_evidence_digest": digests["completion CPU evidence digest"],
            "completion_gpu_evidence_digest": digests["completion GPU evidence digest"],
            "completion_gpu_identity_set_digest": digests[
                "completion GPU identity-set digest"
            ],
            "channel_binding_digest": digests["channel binding digest"],
            "result_digest": digests["result digest"],
            "artifact_manifest_digest": digests["artifact manifest digest"],
            "secret_release_grant_digest": digests["secret-release grant digest"],
            "outcome": outcome,
            "deletion_confirmed": deletion_confirmed,
            "deletion_evidence_digest": digests["deletion evidence digest"],
            "policy_registry_release": self.registry.release,
            "policy_registry_digest": self.registry.digest,
            "issued_at": when_text,
            "signing_key_id": self.signing_key_id,
        }
        receipt_id = "cc-gpu-receipt-sha256:" + hashlib.sha256(
            _id_material(document)
        ).hexdigest()
        document["receipt_id"] = receipt_id
        document["signature"] = {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(
                self._private_key.sign(_unsigned_bytes(document))
            ).decode("ascii"),
        }
        try:
            receipt_bytes = canonical_json(document)
        except PolicyRegistryError as exc:
            raise CcGpuReceiptError("schema", "CC-GPU receipt is not canonical") from exc
        return CcGpuJobReceipt(
            receipt_id,
            receipt_bytes,
            sha256_digest(receipt_bytes),
            MappingProxyType(document),
        )


def verify_cc_gpu_job_receipt(
    data: bytes | str,
    policy_registry: PolicyRegistrySnapshot,
    *,
    allowed_profile_authorities: frozenset[str],
    at: datetime | None = None,
    max_age_seconds: int = MAX_CC_GPU_RECEIPT_AGE_SECONDS,
    key_registry: PolicyRegistrySnapshot | None = None,
    replay_guard: CcGpuReceiptReplayGuard | None = None,
) -> CcGpuJobReceipt:
    """Verify one reward-eligible CC-GPU receipt and optionally claim uniqueness."""

    if not isinstance(policy_registry, PolicyRegistrySnapshot) or not policy_registry.signature_verified:
        raise CcGpuReceiptError("policy", "verified receipt policy registry is required")
    if (
        not isinstance(allowed_profile_authorities, frozenset)
        or not allowed_profile_authorities
        or any(_PROFILE_AUTHORITY_RE.fullmatch(value) is None for value in allowed_profile_authorities)
    ):
        raise CcGpuReceiptError("policy", "active CC-GPU profile authorities are required")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0:
        raise CcGpuReceiptError("policy", "receipt freshness window is invalid")
    try:
        document = parse_receipt_json(data)
    except ReceiptError as exc:
        raise CcGpuReceiptError(exc.category, str(exc)) from exc
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    try:
        canonical_input = canonical_json(document)
    except PolicyRegistryError as exc:
        raise CcGpuReceiptError("schema", "CC-GPU receipt is not canonical") from exc
    if encoded != canonical_input or frozenset(document) != _TOP_KEYS:
        raise CcGpuReceiptError("schema", "CC-GPU receipt has non-canonical or unknown fields")
    if document["schema"] != CC_GPU_JOB_RECEIPT_SCHEMA:
        raise CcGpuReceiptError("schema", "CC-GPU receipt schema is unsupported")
    if document["execution_class"] != CC_GPU_EXECUTION_CLASS:
        raise CcGpuReceiptError("execution_class", "hybrid or CPU receipts are not CC-GPU receipts")
    context = CcGpuJobContext(
        worker_id=_require_worker_id(document["worker_id"]),
        subject_hotkey=_require_subject_hotkey(document["subject_hotkey"]),
        job_id=_require_job_id(document["job_id"]),
        attempt_id=_require_attempt_id(document["attempt_id"]),
        profile_id=document["profile_id"],
        provider=document["provider"],
        machine_type=document["machine_type"],
        zone=document["zone"],
        cpu_tee=document["cpu_tee"],
        gpu_model=document["gpu_model"],
        gpu_count=document["gpu_count"],
        provisioning_model=document["provisioning_model"],
        profile_authority=_require_profile_authority(document["profile_authority"]),
        image_digest=_require_digest(document["image_digest"], "image digest"),
        policy_digest=_require_digest(document["policy_digest"], "policy digest"),
        input_digest=_require_digest(document["input_digest"], "input digest"),
        model_digest=_require_digest(document["model_digest"], "model digest"),
    )
    if document["job_context_digest"] != context.digest:
        raise CcGpuReceiptError("binding", "CC-GPU job context digest is mismatched")
    if context.profile_authority not in allowed_profile_authorities:
        raise CcGpuReceiptError("policy", "CC-GPU profile authority is not active")
    digest_names = (
        "admission_bundle_digest",
        "admission_nonce_digest",
        "admission_cpu_evidence_digest",
        "admission_gpu_evidence_digest",
        "admission_gpu_identity_set_digest",
        "completion_bundle_digest",
        "completion_nonce_digest",
        "completion_cpu_evidence_digest",
        "completion_gpu_evidence_digest",
        "completion_gpu_identity_set_digest",
        "channel_binding_digest",
        "result_digest",
        "artifact_manifest_digest",
        "secret_release_grant_digest",
        "deletion_evidence_digest",
    )
    for name in digest_names:
        _require_digest(document[name], name.replace("_", " "))
    evidence_values = {
        document[name]
        for name in (
            "admission_bundle_digest",
            "admission_cpu_evidence_digest",
            "admission_gpu_evidence_digest",
            "completion_bundle_digest",
            "completion_cpu_evidence_digest",
            "completion_gpu_evidence_digest",
        )
    }
    if len(evidence_values) != 6:
        raise CcGpuReceiptError("replay", "CC-GPU admission or completion evidence was reused")
    if document["admission_nonce_digest"] == document["completion_nonce_digest"]:
        raise CcGpuReceiptError("replay", "CC-GPU admission or completion nonce was reused")
    if (
        document["admission_gpu_identity_set_digest"]
        != document["completion_gpu_identity_set_digest"]
    ):
        raise CcGpuReceiptError(
            "binding", "CC-GPU admission and completion GPU identity sets differ"
        )
    if document["outcome"] != CC_GPU_COMPLETED_OUTCOME:
        raise CcGpuReceiptError("outcome", "CC-GPU receipt is not completed")
    if document["deletion_confirmed"] is not True:
        raise CcGpuReceiptError("deletion", "CC-GPU provider deletion is not confirmed")
    issued_at = _parse_time(document["issued_at"], "receipt issued_at")
    current = at if at is not None else datetime.now(UTC)
    _canonical_time(current, "receipt verification time")
    if issued_at > current or current - issued_at >= timedelta(seconds=max_age_seconds):
        raise CcGpuReceiptError("stale", "CC-GPU receipt is stale or from the future")
    release = document["policy_registry_release"]
    if (
        isinstance(release, bool)
        or not isinstance(release, int)
        or release <= 0
        or release != policy_registry.release
        or document["policy_registry_digest"] != policy_registry.digest
        or not policy_registry.valid_from <= issued_at < policy_registry.valid_until
    ):
        raise CcGpuReceiptError("policy", "CC-GPU receipt policy registry is mismatched")
    receipt_id = document["receipt_id"]
    expected_id = "cc-gpu-receipt-sha256:" + hashlib.sha256(
        _id_material(document)
    ).hexdigest()
    if (
        not isinstance(receipt_id, str)
        or _RECEIPT_ID_RE.fullmatch(receipt_id) is None
        or receipt_id != expected_id
    ):
        raise CcGpuReceiptError("schema", "CC-GPU receipt id is mismatched")
    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise CcGpuReceiptError("signature", "CC-GPU receipt signature is invalid")
    if signature["algorithm"] != "ed25519":
        raise CcGpuReceiptError("signature", "CC-GPU receipt signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise CcGpuReceiptError("signature", "CC-GPU receipt signature is invalid") from exc
    if (
        len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii") != signature["value_base64"]
    ):
        raise CcGpuReceiptError("signature", "CC-GPU receipt signature is invalid")
    key_id = document["signing_key_id"]
    policy_key = policy_registry.receipt_key(key_id) if isinstance(key_id, str) else None
    trust_registry = key_registry or policy_registry
    if not isinstance(trust_registry, PolicyRegistrySnapshot) or not trust_registry.signature_verified:
        raise CcGpuReceiptError("key", "verified CC-GPU key registry is required")
    if trust_registry.release < policy_registry.release:
        raise CcGpuReceiptError("key", "CC-GPU key registry predates its policy registry")
    trust_key = trust_registry.receipt_key(key_id) if isinstance(key_id, str) else None
    if (
        policy_key is None
        or trust_key is None
        or policy_key.public_key != trust_key.public_key
        or not trust_key.can_verify_at(issued_at)
    ):
        raise CcGpuReceiptError("key", "CC-GPU receipt signing key is not trusted")
    try:
        Ed25519PublicKey.from_public_bytes(trust_key.public_key).verify(
            signature_bytes,
            _unsigned_bytes(document),
        )
    except (InvalidSignature, ValueError) as exc:
        raise CcGpuReceiptError("signature", "CC-GPU receipt signature verification failed") from exc
    if replay_guard is not None:
        if not isinstance(replay_guard, CcGpuReceiptReplayGuard):
            raise CcGpuReceiptError("schema", "CC-GPU replay guard is invalid")
        replay_guard.claim(document)
    return CcGpuJobReceipt(
        receipt_id,
        canonical_input,
        sha256_digest(canonical_input),
        MappingProxyType(document),
    )
