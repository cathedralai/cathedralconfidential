"""Digest-pinned workload admission and provider-neutral execution contracts.

This module does not run customer containers. It turns an immutable OCI image
reference plus an external signature verdict into a typed, capability-bound
manifest that future execution and key-release adapters can consume without
resolving mutable tags.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence


LOGGER = logging.getLogger(__name__)

WORKLOAD_MANIFEST_SCHEMA = "cathedral_workload_manifest_v1"
WORKLOAD_POLICY_SCHEMA = "cathedral_workload_admission_policy_v1"
VERIFIER_REQUEST_SCHEMA = "cathedral_workload_signature_request_v1"
VERIFIER_RESULT_SCHEMA = "cathedral_workload_signature_result_v1"
VERIFIER_PREFLIGHT_SCHEMA = "cathedral_workload_verifier_preflight_v1"
VERIFIER_PREFLIGHT_RESULT_SCHEMA = "cathedral_workload_verifier_preflight_result_v1"

MAX_REFERENCE_LENGTH = 512
MAX_REPOSITORY_LENGTH = 255
MAX_ARTIFACT_DIGESTS = 64
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_REGISTRY_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_REPOSITORY_COMPONENT_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
_SENSITIVE_ARGUMENT_RE = re.compile(
    r"(?i)(?:^--?)?(?:password|passwd|token|secret|api[_-]?key|credential)(?:=|$)"
)


class WorkloadAdmissionError(ValueError):
    """A workload failed a stable, customer-safe admission category."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


class SignatureVerifierError(RuntimeError):
    """The external signature-verification boundary failed closed."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _canonical_json(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(document),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _validate_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise WorkloadAdmissionError("invalid_manifest", f"{name} must be a SHA-256 digest")
    return value


def _validate_id(value: object, name: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise WorkloadAdmissionError("invalid_policy", f"{name} is invalid")
    return value


def _validate_identity(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise WorkloadAdmissionError("invalid_policy", f"{name} is invalid")
    return value


def _validate_registry(registry: object, *, production: bool) -> str:
    if (
        not isinstance(registry, str)
        or not 1 <= len(registry) <= 253
        or registry != registry.lower()
        or ":" in registry
    ):
        raise WorkloadAdmissionError("invalid_image_reference", "image registry is invalid")
    labels = registry.split(".")
    if any(_REGISTRY_LABEL_RE.fullmatch(label) is None for label in labels):
        raise WorkloadAdmissionError("invalid_image_reference", "image registry is invalid")
    try:
        ipaddress.ip_address(registry)
    except ValueError:
        pass
    else:
        raise WorkloadAdmissionError(
            "invalid_image_reference", "IP-literal image registries are unavailable"
        )
    if production and (registry == "localhost" or "." not in registry):
        raise WorkloadAdmissionError(
            "invalid_image_reference", "production image registry must be a DNS name"
        )
    return registry


@dataclass(frozen=True)
class ImageReference:
    """A canonical OCI reference with no mutable tag or transport syntax."""

    registry: str
    repository: str
    digest: str

    @classmethod
    def parse(cls, raw: object, *, production: bool = True) -> ImageReference:
        if (
            not isinstance(raw, str)
            or not 1 <= len(raw) <= MAX_REFERENCE_LENGTH
            or raw != raw.strip()
            or raw.count("@") != 1
            or any(token in raw for token in ("://", "?", "#", "%", "\\"))
            or any(ord(character) < 0x21 or ord(character) == 0x7F for character in raw)
        ):
            raise WorkloadAdmissionError(
                "invalid_image_reference", "image reference must be an immutable OCI digest"
            )
        name, digest = raw.split("@", 1)
        if "/" not in name or ":" in name:
            raise WorkloadAdmissionError(
                "invalid_image_reference", "image reference cannot contain a tag or credentials"
            )
        registry, repository = name.split("/", 1)
        checked_registry = _validate_registry(registry, production=production)
        if (
            not 1 <= len(repository) <= MAX_REPOSITORY_LENGTH
            or repository != repository.lower()
            or repository.startswith("/")
            or repository.endswith("/")
            or any(
                _REPOSITORY_COMPONENT_RE.fullmatch(component) is None
                for component in repository.split("/")
            )
        ):
            raise WorkloadAdmissionError(
                "invalid_image_reference", "image repository is invalid"
            )
        if _DIGEST_RE.fullmatch(digest) is None:
            raise WorkloadAdmissionError(
                "invalid_image_reference", "image digest must use canonical SHA-256"
            )
        checked_digest = digest
        return cls(checked_registry, repository, checked_digest)

    @property
    def canonical(self) -> str:
        return f"{self.registry}/{self.repository}@{self.digest}"


@dataclass(frozen=True)
class WorkloadRequest:
    image_reference: str
    required_signer: str
    arguments_digest: str
    config_digest: str
    resource_profile: str
    runtime_profile: str
    artifact_digests: tuple[str, ...] = ()
    default_service_credentials: bool = False
    host_integration: bool = False
    host_network: bool = False
    privileged: bool = False

    def __post_init__(self) -> None:
        _validate_identity(self.required_signer, "required signer")
        _validate_digest(self.arguments_digest, "arguments digest")
        _validate_digest(self.config_digest, "config digest")
        _validate_id(self.resource_profile, "resource profile")
        _validate_id(self.runtime_profile, "runtime profile")
        if (
            not isinstance(self.artifact_digests, tuple)
            or len(self.artifact_digests) > MAX_ARTIFACT_DIGESTS
            or len(set(self.artifact_digests)) != len(self.artifact_digests)
        ):
            raise WorkloadAdmissionError(
                "invalid_manifest", "artifact digests must be a bounded unique tuple"
            )
        checked = tuple(sorted(_validate_digest(value, "artifact digest") for value in self.artifact_digests))
        object.__setattr__(self, "artifact_digests", checked)
        if any(
            not isinstance(value, bool)
            for value in (
                self.default_service_credentials,
                self.host_integration,
                self.host_network,
                self.privileged,
            )
        ):
            raise WorkloadAdmissionError(
                "invalid_manifest", "runtime isolation controls must be booleans"
            )


@dataclass(frozen=True)
class WorkloadAdmissionPolicy:
    policy_id: str
    allowed_registries: frozenset[str]
    allowed_signers: frozenset[str]
    trusted_root_ids: frozenset[str]
    allowed_resource_profiles: frozenset[str]
    allowed_runtime_profiles: frozenset[str]

    def __post_init__(self) -> None:
        _validate_id(self.policy_id, "policy id")
        collections: tuple[tuple[str, frozenset[str]], ...] = (
            ("allowed registries", self.allowed_registries),
            ("allowed signers", self.allowed_signers),
            ("trusted root ids", self.trusted_root_ids),
            ("allowed resource profiles", self.allowed_resource_profiles),
            ("allowed runtime profiles", self.allowed_runtime_profiles),
        )
        for name, values in collections:
            if not isinstance(values, frozenset) or not 1 <= len(values) <= 256:
                raise WorkloadAdmissionError("invalid_policy", f"{name} must be nonempty")
        for registry in self.allowed_registries:
            _validate_registry(registry, production=True)
        for signer in self.allowed_signers:
            _validate_identity(signer, "allowed signer")
        for root_id in self.trusted_root_ids:
            _validate_id(root_id, "trusted root id")
        for profile in self.allowed_resource_profiles:
            _validate_id(profile, "resource profile")
        for profile in self.allowed_runtime_profiles:
            _validate_id(profile, "runtime profile")

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "allowed_registries": sorted(self.allowed_registries),
                "allowed_resource_profiles": sorted(self.allowed_resource_profiles),
                "allowed_runtime_profiles": sorted(self.allowed_runtime_profiles),
                "allowed_signers": sorted(self.allowed_signers),
                "policy_id": self.policy_id,
                "schema": WORKLOAD_POLICY_SCHEMA,
                "trusted_root_ids": sorted(self.trusted_root_ids),
            }
        )

    @property
    def digest(self) -> str:
        return _sha256(_canonical_json(self.document()))


@dataclass(frozen=True)
class SignatureVerdict:
    image_reference: str
    signer_identity: str
    trust_root_id: str
    signature_digest: str

    def __post_init__(self) -> None:
        ImageReference.parse(self.image_reference, production=False)
        _validate_identity(self.signer_identity, "signer identity")
        _validate_id(self.trust_root_id, "trust root id")
        _validate_digest(self.signature_digest, "signature digest")


class SignatureVerifier(Protocol):
    production_capable: bool

    def preflight(self, trusted_root_ids: frozenset[str]) -> None: ...

    def verify(
        self,
        image: ImageReference,
        *,
        required_signer: str,
        trusted_root_ids: frozenset[str],
    ) -> SignatureVerdict: ...


def _reject_duplicate_pairs(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise SignatureVerifierError("malformed_output", "signature verifier output is invalid")
        document[key] = value
    return document


def _reject_float(_value: str) -> object:
    raise SignatureVerifierError("malformed_output", "signature verifier output is invalid")


def _parse_verifier_document(data: bytes) -> dict[str, object]:
    body = data[:-1] if data.endswith(b"\n") else data
    if not body or b"\n" in body:
        raise SignatureVerifierError("malformed_output", "signature verifier output is invalid")
    try:
        document = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except SignatureVerifierError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignatureVerifierError(
            "malformed_output", "signature verifier output is invalid"
        ) from exc
    if not isinstance(document, dict) or _canonical_json(document) != body:
        raise SignatureVerifierError(
            "malformed_output", "signature verifier output is not canonical"
        )
    return document


@dataclass(frozen=True)
class ExternalVerifierConfig:
    command: tuple[str, ...]
    timeout_seconds: float = 10.0
    maximum_output_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if (
            not isinstance(self.command, tuple)
            or not 1 <= len(self.command) <= 32
            or any(
                not isinstance(argument, str)
                or not argument
                or len(argument) > 4096
                or "\x00" in argument
                or "\n" in argument
                or _SENSITIVE_ARGUMENT_RE.search(argument) is not None
                for argument in self.command
            )
            or not os.path.isabs(self.command[0])
        ):
            raise ValueError(
                "signature verifier command must be an absolute credential-free argv tuple"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 60
        ):
            raise ValueError("signature verifier timeout must be between 0 and 60 seconds")
        if (
            isinstance(self.maximum_output_bytes, bool)
            or not isinstance(self.maximum_output_bytes, int)
            or not 256 <= self.maximum_output_bytes <= MAX_VERIFIER_OUTPUT_BYTES
        ):
            raise ValueError("signature verifier output bound is invalid")


class ExternalSignatureVerifier:
    """A shell-free, timeout- and output-bounded JSON verifier protocol."""

    production_capable = True

    def __init__(self, config: ExternalVerifierConfig):
        self.config = config

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if process.poll() is None:
                process.kill()
        if process.poll() is None:
            process.wait()

    def _invoke(self, request: Mapping[str, object]) -> dict[str, object]:
        payload = _canonical_json(request) + b"\n"
        try:
            process = subprocess.Popen(
                self.config.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise SignatureVerifierError(
                "unavailable", "signature verifier is unavailable"
            ) from exc
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except BrokenPipeError:
                process.stdin.close()

            selected = selectors.DefaultSelector()
            output = bytearray()
            deadline = time.monotonic() + float(self.config.timeout_seconds)
            try:
                os.set_blocking(process.stdout.fileno(), False)
                os.set_blocking(process.stderr.fileno(), False)
                selected.register(process.stdout, selectors.EVENT_READ, "stdout")
                selected.register(process.stderr, selectors.EVENT_READ, "stderr")
                total = 0
                while selected.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._terminate(process)
                        raise SignatureVerifierError(
                            "timeout", "signature verifier exceeded its timeout"
                        )
                    events = selected.select(min(remaining, 0.1))
                    for key, _mask in events:
                        try:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selected.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > self.config.maximum_output_bytes:
                            self._terminate(process)
                            raise SignatureVerifierError(
                                "oversized_output",
                                "signature verifier output exceeded its bound",
                            )
                        if key.data == "stdout":
                            output.extend(chunk)
            finally:
                selected.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate(process)
                raise SignatureVerifierError(
                    "timeout", "signature verifier exceeded its timeout"
                )
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                self._terminate(process)
                raise SignatureVerifierError(
                    "timeout", "signature verifier exceeded its timeout"
                ) from exc
            if return_code != 0:
                raise SignatureVerifierError(
                    "nonzero_exit", "signature verifier rejected the request"
                )
            return _parse_verifier_document(bytes(output))
        finally:
            if process.poll() is None:
                self._terminate(process)
            process.stdout.close()
            process.stderr.close()

    def preflight(self, trusted_root_ids: frozenset[str]) -> None:
        document = self._invoke(
            {
                "schema": VERIFIER_PREFLIGHT_SCHEMA,
                "trusted_root_ids": sorted(trusted_root_ids),
            }
        )
        expected_keys = {"protocol_version", "schema", "status", "trust_root_ids"}
        roots = document.get("trust_root_ids")
        if (
            set(document) != expected_keys
            or document.get("schema") != VERIFIER_PREFLIGHT_RESULT_SCHEMA
            or document.get("status") != "ready"
            or isinstance(document.get("protocol_version"), bool)
            or not isinstance(document.get("protocol_version"), int)
            or document.get("protocol_version") != 1
            or not isinstance(roots, list)
            or any(not isinstance(root, str) for root in roots)
            or len(set(roots)) != len(roots)
            or set(roots) != set(trusted_root_ids)
        ):
            raise SignatureVerifierError(
                "preflight_failed", "signature verifier preflight failed"
            )

    def verify(
        self,
        image: ImageReference,
        *,
        required_signer: str,
        trusted_root_ids: frozenset[str],
    ) -> SignatureVerdict:
        document = self._invoke(
            {
                "image_reference": image.canonical,
                "required_signer": required_signer,
                "schema": VERIFIER_REQUEST_SCHEMA,
                "trusted_root_ids": sorted(trusted_root_ids),
            }
        )
        expected_keys = {
            "image_reference",
            "schema",
            "signature_digest",
            "signer_identity",
            "status",
            "trust_root_id",
        }
        if (
            set(document) != expected_keys
            or document.get("schema") != VERIFIER_RESULT_SCHEMA
            or document.get("status") != "verified"
        ):
            raise SignatureVerifierError(
                "invalid_verdict", "signature verifier verdict is invalid"
            )
        try:
            return SignatureVerdict(
                image_reference=document["image_reference"],  # type: ignore[arg-type]
                signer_identity=document["signer_identity"],  # type: ignore[arg-type]
                trust_root_id=document["trust_root_id"],  # type: ignore[arg-type]
                signature_digest=document["signature_digest"],  # type: ignore[arg-type]
            )
        except (KeyError, WorkloadAdmissionError) as exc:
            raise SignatureVerifierError(
                "invalid_verdict", "signature verifier verdict is invalid"
            ) from exc


class LocalSignatureVerifier:
    """Deterministic development verifier; deliberately unavailable in production."""

    production_capable = False

    def __init__(self, verdicts: Mapping[str, SignatureVerdict]):
        self._verdicts = dict(verdicts)
        self.calls = 0

    def preflight(self, trusted_root_ids: frozenset[str]) -> None:
        available = {verdict.trust_root_id for verdict in self._verdicts.values()}
        if not trusted_root_ids <= available:
            raise SignatureVerifierError(
                "preflight_failed", "development signature verifier lacks a trust root"
            )

    def verify(
        self,
        image: ImageReference,
        *,
        required_signer: str,
        trusted_root_ids: frozenset[str],
    ) -> SignatureVerdict:
        self.calls += 1
        verdict = self._verdicts.get(image.canonical)
        if verdict is None:
            raise SignatureVerifierError("not_verified", "image signature is not verified")
        return verdict


@dataclass(frozen=True)
class WorkloadManifest:
    image: ImageReference
    signer_identity: str
    trust_root_id: str
    signature_digest: str
    policy_id: str
    policy_digest: str
    arguments_digest: str
    config_digest: str
    resource_profile: str
    runtime_profile: str
    artifact_digests: tuple[str, ...] = ()
    default_service_credentials: bool = False
    host_integration: bool = False
    host_network: bool = False
    privileged: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.image, ImageReference):
            raise WorkloadAdmissionError("invalid_manifest", "manifest image is invalid")
        _validate_identity(self.signer_identity, "signer identity")
        _validate_id(self.trust_root_id, "trust root id")
        _validate_digest(self.signature_digest, "signature digest")
        _validate_id(self.policy_id, "policy id")
        _validate_digest(self.policy_digest, "policy digest")
        _validate_digest(self.arguments_digest, "arguments digest")
        _validate_digest(self.config_digest, "config digest")
        _validate_id(self.resource_profile, "resource profile")
        _validate_id(self.runtime_profile, "runtime profile")
        if (
            not isinstance(self.artifact_digests, tuple)
            or tuple(sorted(self.artifact_digests)) != self.artifact_digests
            or len(set(self.artifact_digests)) != len(self.artifact_digests)
            or len(self.artifact_digests) > MAX_ARTIFACT_DIGESTS
        ):
            raise WorkloadAdmissionError("invalid_manifest", "manifest artifacts are invalid")
        for digest in self.artifact_digests:
            _validate_digest(digest, "artifact digest")
        if any(
            not isinstance(value, bool)
            for value in (
                self.default_service_credentials,
                self.host_integration,
                self.host_network,
                self.privileged,
            )
        ):
            raise WorkloadAdmissionError(
                "invalid_manifest", "manifest runtime isolation controls are invalid"
            )

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "arguments_digest": self.arguments_digest,
                "artifact_digests": list(self.artifact_digests),
                "config_digest": self.config_digest,
                "default_service_credentials": self.default_service_credentials,
                "host_integration": self.host_integration,
                "host_network": self.host_network,
                "image_digest": self.image.digest,
                "image_reference": self.image.canonical,
                "policy_digest": self.policy_digest,
                "policy_id": self.policy_id,
                "privileged": self.privileged,
                "registry": self.image.registry,
                "repository": self.image.repository,
                "resource_profile": self.resource_profile,
                "runtime_profile": self.runtime_profile,
                "schema": WORKLOAD_MANIFEST_SCHEMA,
                "signature_digest": self.signature_digest,
                "signer_identity": self.signer_identity,
                "trust_root_id": self.trust_root_id,
            }
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document())

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True)
class AdmittedWorkload:
    manifest: WorkloadManifest
    admission_mode: str
    _capability: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.manifest, WorkloadManifest)
            or self.admission_mode not in {"enforced", "development_bypass"}
            or not isinstance(self._capability, str)
            or re.fullmatch(r"admission-hmac-sha256:[0-9a-f]{64}", self._capability)
            is None
        ):
            raise WorkloadAdmissionError(
                "invalid_admission", "admitted workload capability is malformed"
            )

    @property
    def manifest_digest(self) -> str:
        return self.manifest.digest


@dataclass(frozen=True)
class WorkloadExecutionResult:
    manifest_digest: str
    status: str

    def __post_init__(self) -> None:
        _validate_digest(self.manifest_digest, "execution manifest digest")
        if self.status not in {"accepted", "completed"}:
            raise WorkloadAdmissionError("execution_failed", "execution result is invalid")


class WorkloadExecutionAdapter(Protocol):
    def execute(self, workload: AdmittedWorkload) -> WorkloadExecutionResult: ...


class RecordingExecutionAdapter:
    """Safe local adapter: records admitted manifests and executes no process."""

    def __init__(self) -> None:
        self.workloads: list[AdmittedWorkload] = []

    def execute(self, workload: AdmittedWorkload) -> WorkloadExecutionResult:
        if not isinstance(workload, AdmittedWorkload):
            raise WorkloadAdmissionError(
                "execution_denied", "execution requires an admitted workload"
            )
        self.workloads.append(workload)
        return WorkloadExecutionResult(workload.manifest_digest, "accepted")


@dataclass(frozen=True)
class AdmissionDecision:
    status: str
    category: str | None
    manifest_digest: str | None

    def public_dict(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "category": self.category,
                "manifest_digest": self.manifest_digest,
                "status": self.status,
            }
        )


AuditSink = Callable[[Mapping[str, object]], None]


class WorkloadAdmissionController:
    """Evaluate policy and mint short-lived in-process execution capabilities."""

    def __init__(
        self,
        policy: WorkloadAdmissionPolicy,
        verifier: SignatureVerifier,
        *,
        production_mode: bool = True,
        audit_sink: AuditSink | None = None,
        capability_key: bytes | None = None,
    ):
        if not isinstance(policy, WorkloadAdmissionPolicy):
            raise TypeError("policy must be a WorkloadAdmissionPolicy")
        if not isinstance(production_mode, bool):
            raise TypeError("production_mode must be a boolean")
        production_capable = getattr(verifier, "production_capable", None)
        if not isinstance(production_capable, bool):
            raise TypeError("verifier must declare production_capable")
        if production_mode and not production_capable:
            raise WorkloadAdmissionError(
                "verifier_unavailable",
                "development signature verifier is unavailable in production",
            )
        if capability_key is None:
            capability_key = secrets.token_bytes(32)
        if not isinstance(capability_key, bytes) or len(capability_key) < 32:
            raise ValueError("workload capability key must contain at least 32 bytes")
        if audit_sink is not None and not callable(audit_sink):
            raise TypeError("audit_sink must be callable")
        self.policy = policy
        self.verifier = verifier
        self.production_mode = production_mode
        self.audit_sink = audit_sink
        self._capability_key = capability_key
        self._preflight_complete = False
        if production_mode:
            self.startup_preflight()

    def _audit(
        self,
        status: str,
        category: str | None,
        manifest_digest: str | None,
        *,
        reason_digest: str | None = None,
    ) -> None:
        if self.audit_sink is not None:
            event: dict[str, object] = {
                "category": category,
                "manifest_digest": manifest_digest,
                "policy_digest": self.policy.digest,
                "policy_id": self.policy.policy_id,
                "status": status,
            }
            if reason_digest is not None:
                event["reason_digest"] = reason_digest
            self.audit_sink(MappingProxyType(event))

    def startup_preflight(self) -> None:
        try:
            self.verifier.preflight(self.policy.trusted_root_ids)
        except SignatureVerifierError as exc:
            self._audit("denied", exc.category, None)
            raise WorkloadAdmissionError(
                "verifier_unavailable", "signature verifier preflight failed"
            ) from exc
        except Exception as exc:
            self._audit("denied", "unexpected_verifier_failure", None)
            raise WorkloadAdmissionError(
                "verifier_unavailable", "signature verifier preflight failed"
            ) from exc
        self._preflight_complete = True

    def _manifest(self, request: WorkloadRequest) -> WorkloadManifest:
        if not isinstance(request, WorkloadRequest):
            raise WorkloadAdmissionError("invalid_manifest", "workload request is invalid")
        image = ImageReference.parse(request.image_reference, production=self.production_mode)
        if image.registry not in self.policy.allowed_registries:
            raise WorkloadAdmissionError("registry_denied", "image registry is not approved")
        if request.required_signer not in self.policy.allowed_signers:
            raise WorkloadAdmissionError("signer_denied", "image signer is not approved")
        if request.resource_profile not in self.policy.allowed_resource_profiles:
            raise WorkloadAdmissionError("resource_denied", "resource profile is not approved")
        if request.runtime_profile not in self.policy.allowed_runtime_profiles:
            raise WorkloadAdmissionError("runtime_denied", "runtime profile is not approved")
        if self.production_mode and any(
            (
                request.default_service_credentials,
                request.host_integration,
                request.host_network,
                request.privileged,
            )
        ):
            raise WorkloadAdmissionError(
                "runtime_denied", "production workload isolation controls are not approved"
            )
        if not self._preflight_complete:
            self.startup_preflight()
        try:
            verdict = self.verifier.verify(
                image,
                required_signer=request.required_signer,
                trusted_root_ids=self.policy.trusted_root_ids,
            )
        except SignatureVerifierError as exc:
            raise WorkloadAdmissionError(
                "signature_denied", "image signature verification failed"
            ) from exc
        except Exception as exc:
            raise WorkloadAdmissionError(
                "signature_denied", "image signature verification failed"
            ) from exc
        if (
            verdict.image_reference != image.canonical
            or verdict.signer_identity != request.required_signer
            or verdict.signer_identity not in self.policy.allowed_signers
            or verdict.trust_root_id not in self.policy.trusted_root_ids
        ):
            raise WorkloadAdmissionError(
                "signature_denied", "image signature verdict does not match the request"
            )
        return WorkloadManifest(
            image=image,
            signer_identity=verdict.signer_identity,
            trust_root_id=verdict.trust_root_id,
            signature_digest=verdict.signature_digest,
            policy_id=self.policy.policy_id,
            policy_digest=self.policy.digest,
            arguments_digest=request.arguments_digest,
            config_digest=request.config_digest,
            resource_profile=request.resource_profile,
            runtime_profile=request.runtime_profile,
            artifact_digests=request.artifact_digests,
            default_service_credentials=request.default_service_credentials,
            host_integration=request.host_integration,
            host_network=request.host_network,
            privileged=request.privileged,
        )

    def _capability(self, manifest: WorkloadManifest, mode: str) -> str:
        material = b"cathedral-workload-admission-v1\0" + mode.encode("ascii") + b"\0"
        digest = hmac.new(
            self._capability_key,
            material + manifest.canonical_bytes,
            hashlib.sha256,
        ).hexdigest()
        return "admission-hmac-sha256:" + digest

    def admit(self, request: WorkloadRequest) -> AdmittedWorkload:
        try:
            manifest = self._manifest(request)
        except WorkloadAdmissionError as exc:
            self._audit("denied", exc.category, None)
            raise
        admitted = AdmittedWorkload(
            manifest,
            "enforced",
            self._capability(manifest, "enforced"),
        )
        self._audit("admitted", None, manifest.digest)
        return admitted

    def audit(self, request: WorkloadRequest) -> AdmissionDecision:
        try:
            manifest = self._manifest(request)
        except WorkloadAdmissionError as exc:
            decision = AdmissionDecision("would_deny", exc.category, None)
            self._audit(decision.status, decision.category, None)
            return decision
        decision = AdmissionDecision("would_admit", None, manifest.digest)
        self._audit(decision.status, None, manifest.digest)
        return decision

    def development_bypass(
        self, request: WorkloadRequest, *, reason: str
    ) -> AdmittedWorkload:
        if self.production_mode:
            raise WorkloadAdmissionError(
                "bypass_denied", "development bypass is unavailable in production"
            )
        if not isinstance(request, WorkloadRequest):
            raise WorkloadAdmissionError("bypass_denied", "workload request is invalid")
        if (
            not isinstance(reason, str)
            or not 1 <= len(reason.strip()) <= 160
            or any(ord(character) < 0x20 for character in reason)
        ):
            raise WorkloadAdmissionError("bypass_denied", "development bypass reason is invalid")
        image = ImageReference.parse(request.image_reference, production=False)
        reason_digest = _sha256(reason.strip().encode("utf-8"))
        manifest = WorkloadManifest(
            image=image,
            signer_identity="development-bypass",
            trust_root_id="development-bypass",
            signature_digest=_sha256(
                b"cathedral-development-bypass-v1\0" + image.canonical.encode("utf-8")
            ),
            policy_id=self.policy.policy_id,
            policy_digest=self.policy.digest,
            arguments_digest=request.arguments_digest,
            config_digest=request.config_digest,
            resource_profile=request.resource_profile,
            runtime_profile=request.runtime_profile,
            artifact_digests=request.artifact_digests,
            default_service_credentials=request.default_service_credentials,
            host_integration=request.host_integration,
            host_network=request.host_network,
            privileged=request.privileged,
        )
        LOGGER.warning(
            "development workload admission bypass used policy_id=%s "
            "manifest_digest=%s reason_digest=%s",
            self.policy.policy_id,
            manifest.digest,
            reason_digest,
        )
        admitted = AdmittedWorkload(
            manifest,
            "development_bypass",
            self._capability(manifest, "development_bypass"),
        )
        self._audit(
            "development_bypass",
            "explicit_operator_bypass",
            manifest.digest,
            reason_digest=reason_digest,
        )
        return admitted

    def dispatch(
        self,
        workload: AdmittedWorkload,
        adapter: WorkloadExecutionAdapter,
    ) -> WorkloadExecutionResult:
        if not isinstance(workload, AdmittedWorkload):
            raise WorkloadAdmissionError(
                "execution_denied", "execution requires an admitted workload"
            )
        if self.production_mode and workload.admission_mode != "enforced":
            raise WorkloadAdmissionError(
                "execution_denied", "production execution requires enforced admission"
            )
        expected = self._capability(workload.manifest, workload.admission_mode)
        if not hmac.compare_digest(workload._capability, expected):
            raise WorkloadAdmissionError(
                "execution_denied", "workload admission capability is invalid"
            )
        result = adapter.execute(workload)
        if (
            not isinstance(result, WorkloadExecutionResult)
            or result.manifest_digest != workload.manifest_digest
        ):
            raise WorkloadAdmissionError(
                "execution_failed", "execution adapter returned a mismatched result"
            )
        return result
