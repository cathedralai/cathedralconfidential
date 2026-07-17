"""Attestation-gated, idempotent release of workload data-key ciphertext.

Production brokers must encrypt inside an external custody boundary. Cathedral
persists only grants, hashes, audit transitions, and ciphertext; it never asks a
production broker to return plaintext key material.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cathedral.assurance import (
    CHANNEL_BINDING_POLICY_DIGEST,
    KEY_RELEASE_POLICY,
    ClaimStatus,
    policy_digest,
    sha256_digest,
)
from cathedral.channel import ChannelBindingError, application_key_binding
from cathedral.common import Attested, ChannelBinding, ChannelBindingType, Policy, Tier
from cathedral.enroll import RegistryStore
from cathedral.lifecycle import WorkerLifecycleState, canonical_utc, parse_utc
from cathedral.workload import (
    AdmittedWorkload,
    WorkloadAdmissionController,
    WorkloadAdmissionError,
    WorkloadAdmissionPolicy,
)


ASSIGNMENT_SCHEMA = "cathedral_authenticated_workload_assignment_v1"
GRANT_SCHEMA = "cathedral_attestation_grant_v1"
BROKER_REQUEST_SCHEMA = "cathedral_key_broker_request_v1"
ENVELOPE_SCHEMA = "cathedral_encrypted_data_key_v1"
ENVELOPE_ALGORITHM = "x25519-hkdf-sha256-aes256gcm-v1"
BROKER_PREFLIGHT_SCHEMA = "cathedral_key_broker_preflight_v1"

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ASSIGNMENT_ID_RE = re.compile(r"assignment-[0-9a-f]{64}")
_GRANT_ID_RE = re.compile(r"grant-[0-9a-f]{64}")
_CAPABILITY_RE = re.compile(r"assignment-hmac-sha256:[0-9a-f]{64}")
_PURPOSE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_ENVELOPE_BYTES = 4096


class KeyReleaseError(RuntimeError):
    """A stable, secret-safe key-release failure."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


class GrantState(str, enum.Enum):
    ISSUED = "issued"
    REDEEMING = "redeeming"
    REDEEMED = "redeemed"


class BrokerCustodyBoundary(str, enum.Enum):
    LOCAL_TEST = "local_test"
    EXTERNAL_KMS = "external_kms"
    SEPARATELY_ATTESTED_BROKER = "separately_attested_broker"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_json(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(document),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _keyed_identity_digest(key: bytes, domain: bytes, value: str) -> str:
    return "sha256:" + hmac.new(
        key,
        domain + b"\0" + value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _x25519_public_key(value: bytes) -> X25519PublicKey:
    if not isinstance(value, bytes) or len(value) != 32:
        raise KeyReleaseError("channel_denied", "application public key must be 32 bytes")
    try:
        public_key = X25519PublicKey.from_public_bytes(value)
        # ``from_public_bytes`` accepts low-order points. A trial exchange rejects
        # keys that can only produce the all-zero shared secret.
        X25519PrivateKey.generate().exchange(public_key)
    except ValueError as exc:
        raise KeyReleaseError("channel_denied", "application public key is invalid") from exc
    return public_key


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise KeyReleaseError("invalid_grant", f"{name} must be a SHA-256 digest")
    return value


def _require_text(value: object, name: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise KeyReleaseError("invalid_assignment", f"{name} is invalid")
    return value


def _require_positive_int(value: object, name: str, *, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise KeyReleaseError("invalid_policy", f"{name} is invalid")
    return value


def _canonical_time(value: datetime, name: str) -> str:
    try:
        return canonical_utc(value)
    except Exception as exc:
        raise KeyReleaseError("invalid_grant", f"{name} must be UTC") from exc


@dataclass(frozen=True)
class BrokerPreflight:
    """Pinned startup assertions returned by a broker adapter."""

    configuration_digest: str
    custody_boundary: BrokerCustodyBoundary
    ciphertext_only: bool
    durable_idempotency: bool
    request_binding: bool
    schema: str = BROKER_PREFLIGHT_SCHEMA

    def __post_init__(self) -> None:
        _require_digest(self.configuration_digest, "broker configuration digest")
        if self.schema != BROKER_PREFLIGHT_SCHEMA:
            raise KeyReleaseError("broker_unavailable", "broker preflight schema is invalid")
        if not isinstance(self.custody_boundary, BrokerCustodyBoundary) or any(
            not isinstance(value, bool)
            for value in (
                self.ciphertext_only,
                self.durable_idempotency,
                self.request_binding,
            )
        ):
            raise KeyReleaseError("broker_unavailable", "broker preflight is invalid")

    def production_ready(self, required_configuration_digest: str) -> bool:
        return (
            self.configuration_digest == required_configuration_digest
            and self.custody_boundary
            in {
                BrokerCustodyBoundary.EXTERNAL_KMS,
                BrokerCustodyBoundary.SEPARATELY_ATTESTED_BROKER,
            }
            and self.ciphertext_only
            and self.durable_idempotency
            and self.request_binding
        )


@dataclass(frozen=True)
class KeyReleasePolicy:
    allowed_purposes: frozenset[str] = frozenset({"sealed_workload_data_key_v1"})
    max_attestation_age_seconds: int = 60
    max_grant_ttl_seconds: int = 60
    clock_skew_seconds: int = 5

    def __post_init__(self) -> None:
        if (
            not isinstance(self.allowed_purposes, frozenset)
            or not 1 <= len(self.allowed_purposes) <= 32
            or any(
                not isinstance(purpose, str) or _PURPOSE_RE.fullmatch(purpose) is None
                for purpose in self.allowed_purposes
            )
        ):
            raise KeyReleaseError("invalid_policy", "key-release purposes are invalid")
        _require_positive_int(
            self.max_attestation_age_seconds,
            "maximum attestation age",
            maximum=60,
        )
        _require_positive_int(
            self.max_grant_ttl_seconds,
            "maximum grant TTL",
            maximum=60,
        )
        if (
            isinstance(self.clock_skew_seconds, bool)
            or not isinstance(self.clock_skew_seconds, int)
            or not 0 <= self.clock_skew_seconds <= 5
        ):
            raise KeyReleaseError("invalid_policy", "clock skew is invalid")

    @property
    def digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "allowed_purposes": sorted(self.allowed_purposes),
                    "clock_skew_seconds": self.clock_skew_seconds,
                    "max_attestation_age_seconds": self.max_attestation_age_seconds,
                    "max_grant_ttl_seconds": self.max_grant_ttl_seconds,
                    "schema": "cathedral_key_release_policy_v1",
                }
            )
        )


@dataclass(frozen=True)
class AuthenticatedWorkloadAssignment:
    assignment_id: str
    issuer_id: str = field(repr=False)
    issuer_digest: str
    worker_hotkey: str
    manifest_digest: str
    workload_policy_digest: str
    production_admission: bool
    purpose: str
    issued_at: datetime
    expires_at: datetime
    data_key_reference: str = field(repr=False)
    data_key_reference_digest: str
    _capability: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.assignment_id, str) or _ASSIGNMENT_ID_RE.fullmatch(
            self.assignment_id
        ) is None:
            raise KeyReleaseError("invalid_assignment", "assignment id is invalid")
        _require_text(self.issuer_id, "assignment issuer")
        _require_digest(self.issuer_digest, "assignment issuer digest")
        _require_text(self.worker_hotkey, "assignment worker")
        _require_digest(self.manifest_digest, "assignment manifest digest")
        _require_digest(self.workload_policy_digest, "assignment policy digest")
        if not isinstance(self.production_admission, bool):
            raise KeyReleaseError(
                "invalid_assignment", "assignment admission provenance is invalid"
            )
        if not isinstance(self.purpose, str) or _PURPOSE_RE.fullmatch(self.purpose) is None:
            raise KeyReleaseError("invalid_assignment", "assignment purpose is invalid")
        _canonical_time(self.issued_at, "assignment issued_at")
        _canonical_time(self.expires_at, "assignment expires_at")
        if self.expires_at <= self.issued_at:
            raise KeyReleaseError("invalid_assignment", "assignment validity is invalid")
        _require_text(self.data_key_reference, "data-key reference")
        _require_digest(self.data_key_reference_digest, "data-key reference digest")
        if not isinstance(self._capability, str) or _CAPABILITY_RE.fullmatch(
            self._capability
        ) is None:
            raise KeyReleaseError("invalid_assignment", "assignment capability is invalid")

    def capability_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "assignment_id": self.assignment_id,
                "data_key_reference_digest": self.data_key_reference_digest,
                "expires_at": canonical_utc(self.expires_at),
                "issued_at": canonical_utc(self.issued_at),
                "issuer_digest": self.issuer_digest,
                "manifest_digest": self.manifest_digest,
                "production_admission": self.production_admission,
                "purpose": self.purpose,
                "schema": ASSIGNMENT_SCHEMA,
                "worker_hotkey": self.worker_hotkey,
                "workload_policy_digest": self.workload_policy_digest,
            }
        )


class WorkloadAssignmentAuthority:
    """Mint assignments only after validating an enforced workload capability."""

    def __init__(
        self,
        workload_controller: WorkloadAdmissionController,
        capability_key: bytes,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(workload_controller, WorkloadAdmissionController):
            raise TypeError("workload_controller is invalid")
        if not isinstance(capability_key, bytes) or len(capability_key) < 32:
            raise ValueError("assignment capability key must contain at least 32 bytes")
        if not callable(clock):
            raise TypeError("assignment clock must be callable")
        self.workload_controller = workload_controller
        self._capability_key = capability_key
        self._clock = clock
        self._production_admission = bool(
            workload_controller.production_mode
            and workload_controller._preflight_complete
            and workload_controller.verifier.production_capable
        )

    @property
    def production_capable(self) -> bool:
        return self._production_admission

    def _sign(self, document: Mapping[str, object]) -> str:
        value = hmac.new(
            self._capability_key,
            b"cathedral-workload-assignment-v1\0" + _canonical_json(document),
            hashlib.sha256,
        ).hexdigest()
        return "assignment-hmac-sha256:" + value

    def issue(
        self,
        *,
        authenticated_issuer_id: str,
        worker_hotkey: str,
        workload: AdmittedWorkload,
        data_key_reference: str,
        purpose: str = "sealed_workload_data_key_v1",
        ttl_seconds: int = 300,
    ) -> AuthenticatedWorkloadAssignment:
        issuer_id = _require_text(authenticated_issuer_id, "authenticated issuer")
        hotkey = _require_text(worker_hotkey, "assigned worker")
        key_reference = _require_text(data_key_reference, "data-key reference")
        if not isinstance(purpose, str) or _PURPOSE_RE.fullmatch(purpose) is None:
            raise KeyReleaseError("invalid_assignment", "assignment purpose is invalid")
        ttl = _require_positive_int(ttl_seconds, "assignment TTL", maximum=600)
        try:
            manifest = self.workload_controller.validate_admission(
                workload,
                require_enforced=True,
                require_production=self._production_admission,
            )
        except WorkloadAdmissionError as exc:
            raise KeyReleaseError(
                "invalid_assignment", "assignment workload is not admitted"
            ) from exc
        if self._production_admission and not workload.production_admission:
            raise KeyReleaseError(
                "invalid_assignment",
                "production assignment requires production workload admission",
            )
        when = self._clock()
        _canonical_time(when, "assignment issue time")
        assignment_id = "assignment-" + secrets.token_hex(32)
        issuer_digest = _keyed_identity_digest(
            self._capability_key,
            b"cathedral-assignment-issuer-v1",
            issuer_id,
        )
        key_digest = _keyed_identity_digest(
            self._capability_key,
            b"cathedral-data-key-reference-v1",
            key_reference,
        )
        values = {
            "assignment_id": assignment_id,
            "issuer_digest": issuer_digest,
            "worker_hotkey": hotkey,
            "manifest_digest": manifest.digest,
            "workload_policy_digest": manifest.policy_digest,
            "production_admission": (
                self._production_admission and workload.production_admission
            ),
            "purpose": purpose,
            "issued_at": when,
            "expires_at": when + timedelta(seconds=ttl),
            "data_key_reference_digest": key_digest,
        }
        unsigned = AuthenticatedWorkloadAssignment(
            **values,
            issuer_id=issuer_id,
            data_key_reference=key_reference,
            _capability="assignment-hmac-sha256:" + "0" * 64,
        )
        return AuthenticatedWorkloadAssignment(
            **values,
            issuer_id=issuer_id,
            data_key_reference=key_reference,
            _capability=self._sign(unsigned.capability_document()),
        )

    def verify(
        self,
        assignment: AuthenticatedWorkloadAssignment,
        *,
        at: datetime,
    ) -> None:
        if not isinstance(assignment, AuthenticatedWorkloadAssignment):
            raise KeyReleaseError("invalid_assignment", "workload assignment is invalid")
        _canonical_time(at, "assignment verification time")
        if not assignment.issued_at <= at < assignment.expires_at:
            raise KeyReleaseError("invalid_assignment", "workload assignment is expired")
        if assignment.issuer_digest != _keyed_identity_digest(
            self._capability_key,
            b"cathedral-assignment-issuer-v1",
            assignment.issuer_id,
        ) or assignment.data_key_reference_digest != _keyed_identity_digest(
            self._capability_key,
            b"cathedral-data-key-reference-v1",
            assignment.data_key_reference,
        ):
            raise KeyReleaseError("invalid_assignment", "workload assignment binding is invalid")
        expected = self._sign(assignment.capability_document())
        if not hmac.compare_digest(assignment._capability, expected):
            raise KeyReleaseError("invalid_assignment", "workload assignment capability is invalid")


@dataclass(frozen=True)
class EncryptedDataKeyEnvelope:
    grant_id: str
    request_digest: str
    ephemeral_public_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    algorithm: str = ENVELOPE_ALGORITHM

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str) or _GRANT_ID_RE.fullmatch(self.grant_id) is None:
            raise KeyReleaseError("invalid_envelope", "envelope grant id is invalid")
        _require_digest(self.request_digest, "broker request digest")
        if self.algorithm != ENVELOPE_ALGORITHM:
            raise KeyReleaseError("invalid_envelope", "envelope algorithm is unsupported")
        for name, encoded, minimum, maximum in (
            ("ephemeral public key", self.ephemeral_public_key_b64, 32, 32),
            ("nonce", self.nonce_b64, 12, 12),
            ("ciphertext", self.ciphertext_b64, 17, 1024),
        ):
            if not isinstance(encoded, str):
                raise KeyReleaseError("invalid_envelope", f"{name} is invalid")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as exc:
                raise KeyReleaseError("invalid_envelope", f"{name} is invalid") from exc
            if (
                not minimum <= len(decoded) <= maximum
                or base64.b64encode(decoded).decode("ascii") != encoded
            ):
                raise KeyReleaseError("invalid_envelope", f"{name} is invalid")

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "algorithm": self.algorithm,
                "ciphertext_b64": self.ciphertext_b64,
                "ephemeral_public_key_b64": self.ephemeral_public_key_b64,
                "grant_id": self.grant_id,
                "nonce_b64": self.nonce_b64,
                "request_digest": self.request_digest,
                "schema": ENVELOPE_SCHEMA,
            }
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document())

    @property
    def digest(self) -> str:
        return _digest(self.canonical_bytes)


@dataclass(frozen=True)
class BrokerRedemptionRequest:
    grant_id: str
    key_reference: str = field(repr=False)
    key_reference_digest: str
    application_public_key: bytes = field(repr=False)
    channel_key_digest: str
    manifest_digest: str
    evidence_digest: str
    grant_digest: str
    purpose: str

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str) or _GRANT_ID_RE.fullmatch(self.grant_id) is None:
            raise KeyReleaseError("invalid_broker_request", "broker grant id is invalid")
        _require_text(self.key_reference, "broker key reference")
        _require_digest(self.key_reference_digest, "broker key-reference digest")
        try:
            _x25519_public_key(self.application_public_key)
        except KeyReleaseError as exc:
            raise KeyReleaseError(
                "invalid_broker_request", "application public key is invalid"
            ) from exc
        for name, value in (
            ("channel-key digest", self.channel_key_digest),
            ("manifest digest", self.manifest_digest),
            ("evidence digest", self.evidence_digest),
            ("grant digest", self.grant_digest),
        ):
            _require_digest(value, name)
        if not isinstance(self.purpose, str) or _PURPOSE_RE.fullmatch(self.purpose) is None:
            raise KeyReleaseError("invalid_broker_request", "broker purpose is invalid")

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "channel_key_digest": self.channel_key_digest,
                "evidence_digest": self.evidence_digest,
                "grant_id": self.grant_id,
                "grant_digest": self.grant_digest,
                "key_reference_digest": self.key_reference_digest,
                "manifest_digest": self.manifest_digest,
                "purpose": self.purpose,
                "schema": BROKER_REQUEST_SCHEMA,
            }
        )

    @property
    def aad(self) -> bytes:
        return _canonical_json(self.document())

    @property
    def digest(self) -> str:
        return _digest(self.aad)


class KeyBroker(Protocol):
    def preflight(self) -> BrokerPreflight: ...

    def redeem(self, request: BrokerRedemptionRequest) -> EncryptedDataKeyEnvelope: ...


class LocalKeyBroker:
    """Test-only broker with idempotent encryption and best-effort zeroization."""

    def __init__(self, data_keys: Mapping[str, bytes], *, identity_digest_key: bytes):
        if not isinstance(data_keys, Mapping) or not data_keys:
            raise ValueError("local broker requires at least one data key")
        if not isinstance(identity_digest_key, bytes) or len(identity_digest_key) < 32:
            raise ValueError("local broker identity digest key must contain at least 32 bytes")
        checked: dict[str, bytearray] = {}
        for reference, value in data_keys.items():
            key = _require_text(reference, "local data-key reference")
            if not isinstance(value, bytes) or not 16 <= len(value) <= 64:
                raise ValueError("local broker data keys must contain 16 to 64 bytes")
            checked[key] = bytearray(value)
        self._data_keys = checked
        self._identity_digest_key = identity_digest_key
        self._cache: dict[str, tuple[str, EncryptedDataKeyEnvelope]] = {}
        self._lock = threading.Lock()
        self.unwrap_count = 0
        self.call_count = 0

    def preflight(self) -> BrokerPreflight:
        if not self._data_keys:
            raise KeyReleaseError("broker_unavailable", "local key broker is unavailable")
        return BrokerPreflight(
            configuration_digest=_digest(b"cathedral-local-test-broker-v1"),
            custody_boundary=BrokerCustodyBoundary.LOCAL_TEST,
            ciphertext_only=True,
            durable_idempotency=False,
            request_binding=True,
        )

    def redeem(self, request: BrokerRedemptionRequest) -> EncryptedDataKeyEnvelope:
        if not isinstance(request, BrokerRedemptionRequest):
            raise KeyReleaseError("broker_rejected", "broker request is invalid")
        with self._lock:
            self.call_count += 1
            cached = self._cache.get(request.grant_id)
            if cached is not None:
                if cached[0] != request.digest:
                    raise KeyReleaseError(
                        "broker_rejected", "grant id was reused with different bindings"
                    )
                return cached[1]
            source = self._data_keys.get(request.key_reference)
            if source is None or request.key_reference_digest != _keyed_identity_digest(
                self._identity_digest_key,
                b"cathedral-data-key-reference-v1",
                request.key_reference,
            ):
                raise KeyReleaseError("broker_rejected", "data key is unavailable")
            plaintext = bytearray(source)
            try:
                recipient = X25519PublicKey.from_public_bytes(
                    request.application_public_key
                )
                ephemeral_private = X25519PrivateKey.generate()
                shared_secret = ephemeral_private.exchange(recipient)
                wrapping_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=bytes.fromhex(request.channel_key_digest.removeprefix("sha256:")),
                    info=b"cathedral-key-release-v1\0" + request.grant_id.encode("ascii"),
                ).derive(shared_secret)
                nonce = os.urandom(12)
                ciphertext = AESGCM(wrapping_key).encrypt(
                    nonce,
                    bytes(plaintext),
                    request.aad,
                )
                ephemeral_public = ephemeral_private.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            except (ValueError, TypeError) as exc:
                raise KeyReleaseError(
                    "broker_rejected", "application key encryption failed"
                ) from exc
            finally:
                plaintext[:] = b"\x00" * len(plaintext)
            envelope = EncryptedDataKeyEnvelope(
                grant_id=request.grant_id,
                request_digest=request.digest,
                ephemeral_public_key_b64=base64.b64encode(ephemeral_public).decode("ascii"),
                nonce_b64=base64.b64encode(nonce).decode("ascii"),
                ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            )
            self._cache[request.grant_id] = (request.digest, envelope)
            self.unwrap_count += 1
            return envelope


@dataclass(frozen=True)
class AttestationGrant:
    grant_id: str
    assignment_id: str
    issuer_digest: str
    worker_hotkey: str
    manifest_digest: str
    measurement_digest: str
    evidence_digest: str
    attestation_policy_release: int
    attestation_policy_digest: str
    verification_policy_digest: str
    key_release_policy_digest: str
    workload_policy_digest: str
    worker_generation: int
    worker_revision: int
    worker_event_id: int
    channel_key_digest: str
    data_key_reference_digest: str
    purpose: str
    issued_at: datetime
    expires_at: datetime
    state: GrantState = GrantState.ISSUED
    revision: int = 1
    envelope: EncryptedDataKeyEnvelope | None = None
    redeemed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str) or _GRANT_ID_RE.fullmatch(self.grant_id) is None:
            raise KeyReleaseError("invalid_grant", "grant id is invalid")
        if not isinstance(self.assignment_id, str) or _ASSIGNMENT_ID_RE.fullmatch(
            self.assignment_id
        ) is None:
            raise KeyReleaseError("invalid_grant", "grant assignment id is invalid")
        for name, value in (
            ("issuer digest", self.issuer_digest),
            ("manifest digest", self.manifest_digest),
            ("measurement digest", self.measurement_digest),
            ("evidence digest", self.evidence_digest),
            ("attestation policy digest", self.attestation_policy_digest),
            ("verification policy digest", self.verification_policy_digest),
            ("key-release policy digest", self.key_release_policy_digest),
            ("workload policy digest", self.workload_policy_digest),
            ("channel-key digest", self.channel_key_digest),
            ("data-key reference digest", self.data_key_reference_digest),
        ):
            _require_digest(value, name)
        _require_text(self.worker_hotkey, "grant worker")
        for name, value in (
            ("attestation policy release", self.attestation_policy_release),
            ("worker generation", self.worker_generation),
            ("worker revision", self.worker_revision),
            ("worker event id", self.worker_event_id),
            ("grant revision", self.revision),
        ):
            _require_positive_int(value, name, maximum=_MAX_SQLITE_INTEGER)
        if not isinstance(self.purpose, str) or _PURPOSE_RE.fullmatch(self.purpose) is None:
            raise KeyReleaseError("invalid_grant", "grant purpose is invalid")
        _canonical_time(self.issued_at, "grant issued_at")
        _canonical_time(self.expires_at, "grant expires_at")
        if self.expires_at <= self.issued_at:
            raise KeyReleaseError("invalid_grant", "grant validity is invalid")
        if not isinstance(self.state, GrantState):
            raise KeyReleaseError("invalid_grant", "grant state is invalid")
        if (self.envelope is None) != (self.state is not GrantState.REDEEMED):
            raise KeyReleaseError("invalid_grant", "grant envelope state is invalid")
        if (self.redeemed_at is None) != (self.state is not GrantState.REDEEMED):
            raise KeyReleaseError("invalid_grant", "grant redemption time is invalid")
        if self.envelope is not None and self.envelope.grant_id != self.grant_id:
            raise KeyReleaseError("invalid_grant", "grant envelope binding is invalid")

    def public_dict(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "assignment_id": self.assignment_id,
                "expires_at": canonical_utc(self.expires_at),
                "grant_id": self.grant_id,
                "issued_at": canonical_utc(self.issued_at),
                "manifest_digest": self.manifest_digest,
                "purpose": self.purpose,
                "schema": GRANT_SCHEMA,
                "state": self.state.value,
                "worker_hotkey": self.worker_hotkey,
            }
        )

    def binding_document(self) -> Mapping[str, object]:
        """Immutable metadata authenticated by the broker ciphertext AAD."""

        return MappingProxyType(
            {
                "assignment_id": self.assignment_id,
                "attestation_policy_digest": self.attestation_policy_digest,
                "attestation_policy_release": self.attestation_policy_release,
                "channel_key_digest": self.channel_key_digest,
                "data_key_reference_digest": self.data_key_reference_digest,
                "evidence_digest": self.evidence_digest,
                "expires_at": canonical_utc(self.expires_at),
                "grant_id": self.grant_id,
                "issued_at": canonical_utc(self.issued_at),
                "issuer_digest": self.issuer_digest,
                "key_release_policy_digest": self.key_release_policy_digest,
                "manifest_digest": self.manifest_digest,
                "measurement_digest": self.measurement_digest,
                "purpose": self.purpose,
                "schema": GRANT_SCHEMA,
                "worker_event_id": self.worker_event_id,
                "worker_generation": self.worker_generation,
                "worker_hotkey": self.worker_hotkey,
                "worker_revision": self.worker_revision,
                "verification_policy_digest": self.verification_policy_digest,
                "workload_policy_digest": self.workload_policy_digest,
            }
        )

    @property
    def binding_digest(self) -> str:
        return _digest(_canonical_json(self.binding_document()))

    @property
    def expected_broker_request_digest(self) -> str:
        return _digest(
            _canonical_json(
                {
                    "channel_key_digest": self.channel_key_digest,
                    "evidence_digest": self.evidence_digest,
                    "grant_digest": self.binding_digest,
                    "grant_id": self.grant_id,
                    "key_reference_digest": self.data_key_reference_digest,
                    "manifest_digest": self.manifest_digest,
                    "purpose": self.purpose,
                    "schema": BROKER_REQUEST_SCHEMA,
                }
            )
        )

    def operator_dict(self) -> Mapping[str, object]:
        result = dict(self.public_dict())
        result.update(
            {
                "attestation_policy_digest": self.attestation_policy_digest,
                "attestation_policy_release": self.attestation_policy_release,
                "channel_key_digest": self.channel_key_digest,
                "data_key_reference_digest": self.data_key_reference_digest,
                "envelope_digest": self.envelope.digest if self.envelope else None,
                "evidence_digest": self.evidence_digest,
                "issuer_digest": self.issuer_digest,
                "key_release_policy_digest": self.key_release_policy_digest,
                "measurement_digest": self.measurement_digest,
                "redeemed_at": (
                    canonical_utc(self.redeemed_at) if self.redeemed_at else None
                ),
                "revision": self.revision,
                "worker_event_id": self.worker_event_id,
                "worker_generation": self.worker_generation,
                "worker_revision": self.worker_revision,
                "verification_policy_digest": self.verification_policy_digest,
                "workload_policy_digest": self.workload_policy_digest,
            }
        )
        return MappingProxyType(result)


class KeyReleaseStore:
    """Durable grants plus append-only audit transitions; never plaintext."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS key_release_grants (
                        grant_id TEXT PRIMARY KEY,
                        assignment_id TEXT NOT NULL UNIQUE,
                        issuer_digest TEXT NOT NULL,
                        worker_hotkey TEXT NOT NULL,
                        manifest_digest TEXT NOT NULL,
                        measurement_digest TEXT NOT NULL,
                        evidence_digest TEXT NOT NULL,
                        attestation_policy_release INTEGER NOT NULL,
                        attestation_policy_digest TEXT NOT NULL,
                        verification_policy_digest TEXT NOT NULL,
                        key_release_policy_digest TEXT NOT NULL,
                        workload_policy_digest TEXT NOT NULL,
                        worker_generation INTEGER NOT NULL,
                        worker_revision INTEGER NOT NULL,
                        worker_event_id INTEGER NOT NULL,
                        channel_key_digest TEXT NOT NULL,
                        data_key_reference_digest TEXT NOT NULL,
                        purpose TEXT NOT NULL,
                        issued_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('issued','redeeming','redeemed')),
                        revision INTEGER NOT NULL,
                        envelope_json BLOB,
                        envelope_digest TEXT,
                        redeemed_at TEXT
                    );
                    CREATE TABLE IF NOT EXISTS key_release_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        grant_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        from_state TEXT,
                        to_state TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        FOREIGN KEY(grant_id) REFERENCES key_release_grants(grant_id),
                        UNIQUE(grant_id, revision)
                    );
                    CREATE TRIGGER IF NOT EXISTS key_release_events_no_update
                    BEFORE UPDATE ON key_release_events
                    BEGIN SELECT RAISE(ABORT, 'key-release events are append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS key_release_events_no_delete
                    BEFORE DELETE ON key_release_events
                    BEGIN SELECT RAISE(ABORT, 'key-release events are append-only'); END;
                    """
                )
        except sqlite3.DatabaseError as exc:
            raise KeyReleaseError("store_unavailable", "key-release store is unavailable") from exc

    @staticmethod
    def _envelope(raw: object) -> EncryptedDataKeyEnvelope | None:
        if raw is None:
            return None
        if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_ENVELOPE_BYTES:
            raise KeyReleaseError("store_corrupt", "persisted key envelope is invalid")
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KeyReleaseError("store_corrupt", "persisted key envelope is invalid") from exc
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "algorithm",
                "ciphertext_b64",
                "ephemeral_public_key_b64",
                "grant_id",
                "nonce_b64",
                "request_digest",
                "schema",
            }
            or document.get("schema") != ENVELOPE_SCHEMA
            or _canonical_json(document) != raw
        ):
            raise KeyReleaseError("store_corrupt", "persisted key envelope is invalid")
        try:
            return EncryptedDataKeyEnvelope(
                grant_id=document["grant_id"],
                request_digest=document["request_digest"],
                ephemeral_public_key_b64=document["ephemeral_public_key_b64"],
                nonce_b64=document["nonce_b64"],
                ciphertext_b64=document["ciphertext_b64"],
                algorithm=document["algorithm"],
            )
        except (KeyError, KeyReleaseError, TypeError) as exc:
            raise KeyReleaseError("store_corrupt", "persisted key envelope is invalid") from exc

    @classmethod
    def _grant(cls, row: sqlite3.Row) -> AttestationGrant:
        try:
            envelope = cls._envelope(row["envelope_json"])
            grant = AttestationGrant(
                grant_id=row["grant_id"],
                assignment_id=row["assignment_id"],
                issuer_digest=row["issuer_digest"],
                worker_hotkey=row["worker_hotkey"],
                manifest_digest=row["manifest_digest"],
                measurement_digest=row["measurement_digest"],
                evidence_digest=row["evidence_digest"],
                attestation_policy_release=row["attestation_policy_release"],
                attestation_policy_digest=row["attestation_policy_digest"],
                verification_policy_digest=row["verification_policy_digest"],
                key_release_policy_digest=row["key_release_policy_digest"],
                workload_policy_digest=row["workload_policy_digest"],
                worker_generation=row["worker_generation"],
                worker_revision=row["worker_revision"],
                worker_event_id=row["worker_event_id"],
                channel_key_digest=row["channel_key_digest"],
                data_key_reference_digest=row["data_key_reference_digest"],
                purpose=row["purpose"],
                issued_at=parse_utc(row["issued_at"]),
                expires_at=parse_utc(row["expires_at"]),
                state=GrantState(row["state"]),
                revision=row["revision"],
                envelope=envelope,
                redeemed_at=(
                    parse_utc(row["redeemed_at"])
                    if row["redeemed_at"] is not None
                    else None
                ),
            )
        except KeyReleaseError:
            raise
        except Exception as exc:
            raise KeyReleaseError("store_corrupt", "persisted grant is invalid") from exc
        if (envelope is None) != (row["envelope_digest"] is None):
            raise KeyReleaseError("store_corrupt", "persisted envelope digest is invalid")
        if envelope is not None and envelope.digest != row["envelope_digest"]:
            raise KeyReleaseError("store_corrupt", "persisted envelope digest is invalid")
        if (
            envelope is not None
            and envelope.request_digest != grant.expected_broker_request_digest
        ):
            raise KeyReleaseError("store_corrupt", "persisted envelope grant binding is invalid")
        return grant

    @staticmethod
    def _immutable(grant: AttestationGrant) -> tuple[object, ...]:
        return (
            grant.assignment_id,
            grant.issuer_digest,
            grant.worker_hotkey,
            grant.manifest_digest,
            grant.measurement_digest,
            grant.evidence_digest,
            grant.attestation_policy_release,
            grant.attestation_policy_digest,
            grant.verification_policy_digest,
            grant.key_release_policy_digest,
            grant.workload_policy_digest,
            grant.worker_generation,
            grant.worker_revision,
            grant.worker_event_id,
            grant.channel_key_digest,
            grant.data_key_reference_digest,
            grant.purpose,
            grant.issued_at,
            grant.expires_at,
        )

    def create_or_get(self, candidate: AttestationGrant) -> AttestationGrant:
        if not isinstance(candidate, AttestationGrant) or candidate.state is not GrantState.ISSUED:
            raise KeyReleaseError("invalid_grant", "new grant must be issued")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM key_release_grants WHERE assignment_id = ?",
                (candidate.assignment_id,),
            ).fetchone()
            if existing is not None:
                current = self._grant(existing)
                if self._immutable(current) != self._immutable(candidate):
                    raise KeyReleaseError(
                        "grant_conflict", "assignment already has a differently bound grant"
                    )
                return current
            connection.execute(
                """
                INSERT INTO key_release_grants(
                    grant_id, assignment_id, issuer_digest, worker_hotkey,
                    manifest_digest, measurement_digest, evidence_digest,
                    attestation_policy_release, attestation_policy_digest,
                    verification_policy_digest, key_release_policy_digest,
                    workload_policy_digest,
                    worker_generation, worker_revision,
                    worker_event_id, channel_key_digest, data_key_reference_digest,
                    purpose, issued_at, expires_at, state, revision
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'issued',1)
                """,
                (
                    candidate.grant_id,
                    candidate.assignment_id,
                    candidate.issuer_digest,
                    candidate.worker_hotkey,
                    candidate.manifest_digest,
                    candidate.measurement_digest,
                    candidate.evidence_digest,
                    candidate.attestation_policy_release,
                    candidate.attestation_policy_digest,
                    candidate.verification_policy_digest,
                    candidate.key_release_policy_digest,
                    candidate.workload_policy_digest,
                    candidate.worker_generation,
                    candidate.worker_revision,
                    candidate.worker_event_id,
                    candidate.channel_key_digest,
                    candidate.data_key_reference_digest,
                    candidate.purpose,
                    canonical_utc(candidate.issued_at),
                    canonical_utc(candidate.expires_at),
                ),
            )
            connection.execute(
                "INSERT INTO key_release_events(grant_id,revision,from_state,to_state,reason,occurred_at) "
                "VALUES (?,1,NULL,'issued','grant_issued',?)",
                (candidate.grant_id, canonical_utc(candidate.issued_at)),
            )
            row = connection.execute(
                "SELECT * FROM key_release_grants WHERE grant_id = ?",
                (candidate.grant_id,),
            ).fetchone()
            assert row is not None
            return self._grant(row)

    def get(self, grant_id: str) -> AttestationGrant:
        if not isinstance(grant_id, str) or _GRANT_ID_RE.fullmatch(grant_id) is None:
            raise KeyReleaseError("invalid_grant", "grant id is invalid")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM key_release_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
        if row is None:
            raise KeyReleaseError("grant_not_found", "grant does not exist")
        return self._grant(row)

    def begin_redemption(self, grant_id: str, *, at: datetime) -> AttestationGrant:
        _canonical_time(at, "redemption time")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM key_release_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if row is None:
                raise KeyReleaseError("grant_not_found", "grant does not exist")
            current = self._grant(row)
            if at >= current.expires_at:
                raise KeyReleaseError("grant_expired", "grant is expired")
            if current.state is not GrantState.ISSUED:
                return current
            revision = current.revision + 1
            updated = connection.execute(
                "UPDATE key_release_grants SET state='redeeming', revision=? "
                "WHERE grant_id=? AND state='issued' AND revision=?",
                (revision, grant_id, current.revision),
            )
            if updated.rowcount != 1:
                raise KeyReleaseError("grant_conflict", "grant redemption raced another writer")
            connection.execute(
                "INSERT INTO key_release_events(grant_id,revision,from_state,to_state,reason,occurred_at) "
                "VALUES (?,?,'issued','redeeming','redemption_started',?)",
                (grant_id, revision, canonical_utc(at)),
            )
            row = connection.execute(
                "SELECT * FROM key_release_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            assert row is not None
            return self._grant(row)

    def persist_redemption(
        self,
        grant_id: str,
        envelope: EncryptedDataKeyEnvelope,
        *,
        at: datetime,
    ) -> AttestationGrant:
        if not isinstance(envelope, EncryptedDataKeyEnvelope):
            raise KeyReleaseError("invalid_envelope", "broker envelope is invalid")
        _canonical_time(at, "redemption persistence time")
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM key_release_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if row is None:
                raise KeyReleaseError("grant_not_found", "grant does not exist")
            current = self._grant(row)
            if at >= current.expires_at:
                raise KeyReleaseError("grant_expired", "grant expired before persistence")
            if current.state is GrantState.REDEEMED:
                if current.envelope is None or current.envelope.digest != envelope.digest:
                    raise KeyReleaseError(
                        "grant_conflict", "broker returned different ciphertext for a grant"
                    )
                return current
            if current.state is not GrantState.REDEEMING:
                raise KeyReleaseError("grant_conflict", "grant is not redeeming")
            if envelope.grant_id != grant_id:
                raise KeyReleaseError("invalid_envelope", "broker envelope grant is mismatched")
            revision = current.revision + 1
            encoded = envelope.canonical_bytes
            if len(encoded) > _MAX_ENVELOPE_BYTES:
                raise KeyReleaseError("invalid_envelope", "broker envelope exceeds its bound")
            updated = connection.execute(
                """
                UPDATE key_release_grants SET state='redeemed', revision=?,
                    envelope_json=?, envelope_digest=?, redeemed_at=?
                WHERE grant_id=? AND state='redeeming' AND revision=?
                """,
                (
                    revision,
                    encoded,
                    envelope.digest,
                    canonical_utc(at),
                    grant_id,
                    current.revision,
                ),
            )
            if updated.rowcount != 1:
                winner = connection.execute(
                    "SELECT * FROM key_release_grants WHERE grant_id = ?", (grant_id,)
                ).fetchone()
                if winner is None:
                    raise KeyReleaseError("grant_conflict", "grant disappeared during redemption")
                persisted = self._grant(winner)
                if persisted.envelope is None or persisted.envelope.digest != envelope.digest:
                    raise KeyReleaseError(
                        "grant_conflict", "concurrent broker ciphertext differs"
                    )
                return persisted
            connection.execute(
                "INSERT INTO key_release_events(grant_id,revision,from_state,to_state,reason,occurred_at) "
                "VALUES (?,?,'redeeming','redeemed','ciphertext_persisted',?)",
                (grant_id, revision, canonical_utc(at)),
            )
            row = connection.execute(
                "SELECT * FROM key_release_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            assert row is not None
            return self._grant(row)

    def history(self, grant_id: str) -> tuple[Mapping[str, object], ...]:
        self.get(grant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id,revision,from_state,to_state,reason,occurred_at "
                "FROM key_release_events WHERE grant_id=? ORDER BY event_id",
                (grant_id,),
            ).fetchall()
        return tuple(MappingProxyType(dict(row)) for row in rows)


class KeyReleaseService:
    """Issue and redeem grants while rechecking lifecycle and active policy."""

    def __setattr__(self, name: str, value: object) -> None:
        if (
            self.__dict__.get("_configuration_locked", False)
            and name
            in {
                "_LOCKED_SECURITY_CONFIGURATION",
                "_broker",
                "_clock",
                "_clock_lock",
                "_configuration_locked",
                "_last_seen_time",
                "_production_mode",
                "_required_broker_configuration_digest",
                "_sealed_workloads_enabled",
                "assignment_authority",
                "policy",
                "registry",
                "store",
            }
        ):
            raise AttributeError("key-release security configuration is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        store: KeyReleaseStore,
        registry: RegistryStore,
        assignment_authority: WorkloadAssignmentAuthority,
        broker: KeyBroker,
        attestation_policy_provider: Callable[[], Policy],
        workload_policy_provider: Callable[[], WorkloadAdmissionPolicy],
        *,
        policy: KeyReleasePolicy = KeyReleasePolicy(),
        sealed_workloads_enabled: bool = False,
        production_mode: bool = True,
        required_broker_configuration_digest: str | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(store, KeyReleaseStore) or not isinstance(registry, RegistryStore):
            raise TypeError("key-release stores are invalid")
        if not isinstance(assignment_authority, WorkloadAssignmentAuthority):
            raise TypeError("assignment authority is invalid")
        if not callable(getattr(broker, "preflight", None)) or not callable(
            getattr(broker, "redeem", None)
        ):
            raise TypeError("key broker interface is invalid")
        if not callable(attestation_policy_provider) or not callable(
            workload_policy_provider
        ):
            raise TypeError("key-release policy providers must be callable")
        if not isinstance(policy, KeyReleasePolicy):
            raise TypeError("key-release policy is invalid")
        if not isinstance(sealed_workloads_enabled, bool) or not isinstance(
            production_mode, bool
        ):
            raise TypeError("key-release feature flags must be booleans")
        if not callable(clock):
            raise TypeError("key-release clock must be callable")
        if required_broker_configuration_digest is not None and (
            not isinstance(required_broker_configuration_digest, str)
            or _DIGEST_RE.fullmatch(required_broker_configuration_digest) is None
        ):
            raise KeyReleaseError(
                "broker_unavailable", "required broker configuration is invalid"
            )
        if sealed_workloads_enabled and production_mode and (
            required_broker_configuration_digest is None
        ):
            raise KeyReleaseError(
                "broker_unavailable", "production broker configuration is not pinned"
            )
        if (
            sealed_workloads_enabled
            and production_mode
            and not assignment_authority.production_capable
        ):
            raise KeyReleaseError(
                "assignment_unavailable",
                "production workload assignment authority is unavailable",
            )
        self.store = store
        self.registry = registry
        self.assignment_authority = assignment_authority
        self._broker = broker
        self.attestation_policy_provider = attestation_policy_provider
        self.workload_policy_provider = workload_policy_provider
        self.policy = policy
        self._sealed_workloads_enabled = sealed_workloads_enabled
        self._production_mode = production_mode
        self._required_broker_configuration_digest = (
            required_broker_configuration_digest
        )
        self._clock = clock
        self._clock_lock = threading.Lock()
        self._last_seen_time: datetime | None = None
        self._configuration_locked = False
        if sealed_workloads_enabled:
            try:
                preflight = broker.preflight()
            except Exception as exc:
                raise KeyReleaseError(
                    "broker_unavailable", "key broker preflight failed"
                ) from exc
            if not isinstance(preflight, BrokerPreflight):
                raise KeyReleaseError(
                    "broker_unavailable", "key broker preflight is invalid"
                )
            if production_mode:
                assert required_broker_configuration_digest is not None
                if not preflight.production_ready(
                    required_broker_configuration_digest
                ):
                    raise KeyReleaseError(
                        "broker_unavailable", "production broker preflight failed"
                    )
        object.__setattr__(self, "_configuration_locked", True)

    @property
    def broker(self) -> KeyBroker:
        return self._broker

    @property
    def sealed_workloads_enabled(self) -> bool:
        return self._sealed_workloads_enabled

    @property
    def production_mode(self) -> bool:
        return self._production_mode

    @property
    def required_broker_configuration_digest(self) -> str | None:
        return self._required_broker_configuration_digest

    def _now(self) -> datetime:
        with self._clock_lock:
            value = self._clock()
            _canonical_time(value, "key-release time")
            if self._last_seen_time is not None and value < self._last_seen_time:
                raise KeyReleaseError(
                    "clock_invalid", "key-release clock moved backwards"
                )
            object.__setattr__(self, "_last_seen_time", value)
        return value

    def _require_enabled(self) -> None:
        if not self.sealed_workloads_enabled:
            raise KeyReleaseError("feature_disabled", "sealed workload release is disabled")

    def _active_policies(self) -> tuple[Policy, WorkloadAdmissionPolicy]:
        try:
            attestation = self.attestation_policy_provider()
            workload = self.workload_policy_provider()
        except Exception as exc:
            raise KeyReleaseError(
                "policy_unavailable", "active release policy is unavailable"
            ) from exc
        if not isinstance(attestation, Policy) or not isinstance(
            workload, WorkloadAdmissionPolicy
        ):
            raise KeyReleaseError("policy_unavailable", "active release policy is unavailable")
        if attestation.registry_release is None or attestation.registry_digest is None:
            raise KeyReleaseError(
                "policy_unavailable", "signed attestation policy is required for key release"
            )
        return attestation, workload

    @staticmethod
    def _measurement_digest(measurement: str) -> str:
        return _digest(b"cathedral-measurement-v1\0" + measurement.encode("utf-8"))

    def _verified_worker_state(self, hotkey: str):
        try:
            # RegistryStore samples its own clock while holding its lifecycle
            # lock. Passing an earlier service sample can race a concurrent
            # request that already advanced the registry high-water mark.
            lifecycle = self.registry.lifecycle_snapshot(hotkey)
            record = self.registry.verified_attestation_record(hotkey)
        except Exception as exc:
            raise KeyReleaseError(
                "attestation_unavailable", "verified worker state is unavailable"
            ) from exc
        return lifecycle, record

    def _validate_current(self, grant: AttestationGrant, *, at: datetime) -> None:
        attestation_policy, workload_policy = self._active_policies()
        if (
            attestation_policy.registry_release != grant.attestation_policy_release
            or attestation_policy.registry_digest != grant.attestation_policy_digest
            or policy_digest(attestation_policy) != grant.verification_policy_digest
            or self.policy.digest != grant.key_release_policy_digest
            or workload_policy.digest != grant.workload_policy_digest
            or grant.measurement_digest
            not in {
                self._measurement_digest(measurement)
                for measurement in attestation_policy.allowed_measurements
            }
        ):
            raise KeyReleaseError("policy_revoked", "grant policy is no longer active")
        lifecycle, record = self._verified_worker_state(grant.worker_hotkey)
        claims = record.assurance
        channel_claim = claims.channel
        try:
            channel_verified_at = parse_utc(channel_claim.verified_at or "")
            expected_channel_evidence = sha256_digest(
                ChannelBinding(
                    ChannelBindingType.APPLICATION_KEY_SHA256,
                    bytes.fromhex(grant.channel_key_digest.removeprefix("sha256:")),
                ).canonical_bytes()
            )
        except (ValueError, TypeError) as exc:
            raise KeyReleaseError(
                "attestation_revoked", "worker assurance record is invalid"
            ) from exc
        if (
            lifecycle.state is not WorkerLifecycleState.ATTESTED
            or not lifecycle.eligible_at(at)
            or lifecycle.evidence_verified_at is None
            or lifecycle.generation != grant.worker_generation
            or lifecycle.revision != grant.worker_revision
            or lifecycle.event_id != grant.worker_event_id
            or lifecycle.evidence_digest != grant.evidence_digest
            or lifecycle.policy_registry_release != grant.attestation_policy_release
            or lifecycle.policy_registry_digest != grant.attestation_policy_digest
            or lifecycle.policy_digest != grant.verification_policy_digest
            or record.tier != Tier.CC_CPU_TDX.value
            or not KEY_RELEASE_POLICY.allows(claims)
            or claims.hardware.evidence_digest != grant.evidence_digest
            or claims.software.policy_digest != lifecycle.policy_digest
            or channel_claim.policy_digest != CHANNEL_BINDING_POLICY_DIGEST
            or channel_claim.evidence_digest != expected_channel_evidence
            or lifecycle.evidence_verified_at
            > at + timedelta(seconds=self.policy.clock_skew_seconds)
            or at - lifecycle.evidence_verified_at
            >= timedelta(seconds=self.policy.max_attestation_age_seconds)
            or channel_verified_at
            > at + timedelta(seconds=self.policy.clock_skew_seconds)
            or at - channel_verified_at
            >= timedelta(seconds=self.policy.max_attestation_age_seconds)
        ):
            raise KeyReleaseError(
                "attestation_revoked", "worker attestation grant is no longer current"
            )

    def issue_grant(
        self,
        assignment: AuthenticatedWorkloadAssignment,
        attested: Attested,
        application_public_key: bytes,
        *,
        ttl_seconds: int | None = None,
    ) -> AttestationGrant:
        self._require_enabled()
        when = self._now()
        self.assignment_authority.verify(assignment, at=when)
        if self.production_mode and not assignment.production_admission:
            raise KeyReleaseError(
                "invalid_assignment", "production workload assignment is required"
            )
        if assignment.purpose not in self.policy.allowed_purposes:
            raise KeyReleaseError("purpose_denied", "assignment purpose is not approved")
        ttl = (
            self.policy.max_grant_ttl_seconds
            if ttl_seconds is None
            else _require_positive_int(
                ttl_seconds,
                "grant TTL",
                maximum=self.policy.max_grant_ttl_seconds,
            )
        )
        attestation_policy, workload_policy = self._active_policies()
        if assignment.workload_policy_digest != workload_policy.digest:
            raise KeyReleaseError("policy_revoked", "workload admission policy changed")
        lifecycle, record = self._verified_worker_state(assignment.worker_hotkey)
        claims = record.assurance
        if (
            not isinstance(attested, Attested)
            or attested.verification_status != "VERIFIED"
            or attested.tier is not Tier.CC_CPU_TDX
            or record.hotkey != assignment.worker_hotkey
            or record.chip_id != attested.chip_id
            or record.tier != Tier.CC_CPU_TDX.value
            or claims != attested.assurance
            or attested.measurement not in attestation_policy.allowed_measurements
            or not KEY_RELEASE_POLICY.allows(claims)
            or lifecycle.state is not WorkerLifecycleState.ATTESTED
            or not lifecycle.eligible_at(when)
            or lifecycle.evidence_verified_at is None
            or lifecycle.evidence_expires_at is None
            or lifecycle.evidence_digest is None
            or lifecycle.policy_digest is None
            or lifecycle.policy_registry_release != attestation_policy.registry_release
            or lifecycle.policy_registry_digest != attestation_policy.registry_digest
            or lifecycle.evidence_digest != claims.hardware.evidence_digest
            or lifecycle.measurement != attested.measurement
            or lifecycle.policy_digest != claims.software.policy_digest
            or lifecycle.policy_digest != policy_digest(attestation_policy)
        ):
            raise KeyReleaseError(
                "attestation_denied", "worker attestation does not satisfy key-release policy"
            )
        verified_at = lifecycle.evidence_verified_at
        if (
            verified_at > when + timedelta(seconds=self.policy.clock_skew_seconds)
            or when - verified_at
            >= timedelta(seconds=self.policy.max_attestation_age_seconds)
        ):
            raise KeyReleaseError("attestation_stale", "worker attestation is not fresh enough")
        try:
            _x25519_public_key(application_public_key)
            binding = application_key_binding(application_public_key)
        except (KeyReleaseError, ChannelBindingError) as exc:
            raise KeyReleaseError(
                "channel_denied", "application encryption key is invalid"
            ) from exc
        channel_claim = claims.channel
        if (
            binding.binding_type is not ChannelBindingType.APPLICATION_KEY_SHA256
            or channel_claim.status is not ClaimStatus.PASSED
            or channel_claim.evidence_digest != sha256_digest(binding.canonical_bytes())
            or channel_claim.policy_digest != CHANNEL_BINDING_POLICY_DIGEST
            or channel_claim.verified_at is None
        ):
            raise KeyReleaseError(
                "channel_denied", "application key is not bound into fresh attestation"
            )
        try:
            channel_verified_at = parse_utc(channel_claim.verified_at)
        except Exception as exc:
            raise KeyReleaseError(
                "channel_denied", "application key verification time is invalid"
            ) from exc
        if (
            channel_verified_at > when + timedelta(seconds=self.policy.clock_skew_seconds)
            or when - channel_verified_at
            >= timedelta(seconds=self.policy.max_attestation_age_seconds)
        ):
            raise KeyReleaseError("channel_denied", "application key binding is stale")
        expires_at = min(
            when + timedelta(seconds=ttl),
            assignment.expires_at,
            lifecycle.evidence_expires_at,
            verified_at + timedelta(seconds=self.policy.max_attestation_age_seconds),
            channel_verified_at
            + timedelta(seconds=self.policy.max_attestation_age_seconds),
        )
        if expires_at <= when:
            raise KeyReleaseError("grant_expired", "grant has no remaining validity")
        candidate = AttestationGrant(
            grant_id="grant-" + secrets.token_hex(32),
            assignment_id=assignment.assignment_id,
            issuer_digest=assignment.issuer_digest,
            worker_hotkey=assignment.worker_hotkey,
            manifest_digest=assignment.manifest_digest,
            measurement_digest=self._measurement_digest(attested.measurement),
            evidence_digest=lifecycle.evidence_digest,
            attestation_policy_release=attestation_policy.registry_release,
            attestation_policy_digest=attestation_policy.registry_digest,
            verification_policy_digest=lifecycle.policy_digest,
            key_release_policy_digest=self.policy.digest,
            workload_policy_digest=assignment.workload_policy_digest,
            worker_generation=lifecycle.generation,
            worker_revision=lifecycle.revision,
            worker_event_id=lifecycle.event_id,
            channel_key_digest="sha256:" + binding.digest.hex(),
            data_key_reference_digest=assignment.data_key_reference_digest,
            purpose=assignment.purpose,
            issued_at=when,
            expires_at=expires_at,
        )
        return self.store.create_or_get(candidate)

    @staticmethod
    def _assignment_matches(
        grant: AttestationGrant, assignment: AuthenticatedWorkloadAssignment
    ) -> bool:
        return (
            assignment.assignment_id == grant.assignment_id
            and assignment.issuer_digest == grant.issuer_digest
            and assignment.worker_hotkey == grant.worker_hotkey
            and assignment.manifest_digest == grant.manifest_digest
            and assignment.workload_policy_digest == grant.workload_policy_digest
            and assignment.data_key_reference_digest == grant.data_key_reference_digest
            and assignment.purpose == grant.purpose
        )

    def _validate_release_point(
        self,
        grant: AttestationGrant,
        assignment: AuthenticatedWorkloadAssignment,
    ) -> None:
        """Linearization check immediately before ciphertext leaves this service."""

        checked_at = self._now()
        if checked_at >= grant.expires_at:
            raise KeyReleaseError("grant_expired", "grant expired before release")
        self.assignment_authority.verify(assignment, at=checked_at)
        self._validate_current(grant, at=checked_at)
        return_at = self._now()
        if (
            not assignment.issued_at <= return_at < assignment.expires_at
            or return_at >= grant.expires_at
        ):
            raise KeyReleaseError("grant_expired", "grant expired before release")

    def redeem(
        self,
        grant_id: str,
        assignment: AuthenticatedWorkloadAssignment,
        application_public_key: bytes,
    ) -> EncryptedDataKeyEnvelope:
        self._require_enabled()
        when = self._now()
        self.assignment_authority.verify(assignment, at=when)
        if self.production_mode and not assignment.production_admission:
            raise KeyReleaseError(
                "invalid_assignment", "production workload assignment is required"
            )
        grant = self.store.get(grant_id)
        if not self._assignment_matches(grant, assignment):
            raise KeyReleaseError("assignment_denied", "grant assignment does not match")
        try:
            _x25519_public_key(application_public_key)
            binding = application_key_binding(application_public_key)
        except (KeyReleaseError, ChannelBindingError) as exc:
            raise KeyReleaseError("channel_denied", "application key is invalid") from exc
        channel_digest = "sha256:" + binding.digest.hex()
        if (
            binding.binding_type is not ChannelBindingType.APPLICATION_KEY_SHA256
            or channel_digest != grant.channel_key_digest
        ):
            raise KeyReleaseError("channel_denied", "grant application key does not match")
        if when >= grant.expires_at:
            raise KeyReleaseError("grant_expired", "grant is expired")
        self._validate_current(grant, at=when)
        current = self.store.begin_redemption(grant_id, at=when)
        if current.state is GrantState.REDEEMED:
            assert current.envelope is not None
            self._validate_release_point(current, assignment)
            return current.envelope
        request = BrokerRedemptionRequest(
            grant_id=grant.grant_id,
            key_reference=assignment.data_key_reference,
            key_reference_digest=grant.data_key_reference_digest,
            application_public_key=application_public_key,
            channel_key_digest=grant.channel_key_digest,
            manifest_digest=grant.manifest_digest,
            evidence_digest=grant.evidence_digest,
            grant_digest=grant.binding_digest,
            purpose=grant.purpose,
        )
        try:
            envelope = self.broker.redeem(request)
        except Exception as exc:
            raise KeyReleaseError(
                "broker_unavailable", "key broker did not return ciphertext"
            ) from exc
        if (
            not isinstance(envelope, EncryptedDataKeyEnvelope)
            or envelope.grant_id != grant.grant_id
            or envelope.request_digest != request.digest
        ):
            raise KeyReleaseError(
                "broker_rejected", "key broker returned mismatched ciphertext"
            )
        after_broker = self._now()
        if after_broker >= grant.expires_at:
            raise KeyReleaseError("grant_expired", "grant expired during redemption")
        self._validate_current(grant, at=after_broker)
        persisted = self.store.persist_redemption(
            grant_id,
            envelope,
            at=after_broker,
        )
        assert persisted.envelope is not None
        self._validate_release_point(persisted, assignment)
        return persisted.envelope
