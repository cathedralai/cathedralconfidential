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
import socket
import sqlite3
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence


LOGGER = logging.getLogger(__name__)

WORKLOAD_MANIFEST_SCHEMA = "cathedral_workload_manifest_v1"
WORKLOAD_POLICY_SCHEMA = "cathedral_workload_admission_policy_v1"
VERIFIER_REQUEST_SCHEMA = "cathedral_workload_signature_request_v1"
VERIFIER_RESULT_SCHEMA = "cathedral_workload_signature_result_v1"
VERIFIER_PREFLIGHT_SCHEMA = "cathedral_workload_verifier_preflight_v1"
VERIFIER_PREFLIGHT_RESULT_SCHEMA = "cathedral_workload_verifier_preflight_result_v1"
EXECUTION_PREFLIGHT_SCHEMA = "cathedral_workload_execution_preflight_v1"
EXECUTION_PREFLIGHT_RESULT_SCHEMA = "cathedral_workload_execution_preflight_result_v1"
EXECUTION_AUTHORIZATION_SCHEMA = "cathedral_workload_execution_authorization_v1"
EXECUTION_REQUEST_SCHEMA = "cathedral_workload_execution_request_v1"
EXECUTION_RESULT_SCHEMA = "cathedral_workload_execution_result_v1"

MAX_REFERENCE_LENGTH = 512
MAX_REPOSITORY_LENGTH = 255
MAX_ARTIFACT_DIGESTS = 64
MAX_VERIFIER_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_VERIFIER_INPUT_BYTES = 16 * 1024 * 1024
MAX_VERIFIER_INPUT_BYTES = 32 * 1024 * 1024

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_EXECUTION_ID_RE = re.compile(r"(?:assignment|execution)-[0-9a-f]{64}")
_PROVIDER_JOB_ID_RE = re.compile(r"provider-job-[0-9a-f]{64}")
_EXECUTION_AUTHORIZATION_RE = re.compile(r"execution-hmac-sha256:[0-9a-f]{64}")
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


class ExecutionAdapterError(RuntimeError):
    """A production execution-provider boundary failed closed."""

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
            raise WorkloadAdmissionError("invalid_image_reference", "image repository is invalid")
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
        checked = tuple(
            sorted(_validate_digest(value, "artifact digest") for value in self.artifact_digests)
        )
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
    maximum_input_bytes: int = DEFAULT_VERIFIER_INPUT_BYTES
    implementation_artifacts: tuple[str, ...] = ()

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
        if (
            isinstance(self.maximum_input_bytes, bool)
            or not isinstance(self.maximum_input_bytes, int)
            or not 256 <= self.maximum_input_bytes <= MAX_VERIFIER_INPUT_BYTES
        ):
            raise ValueError("signature verifier input bound is invalid")
        if (
            not isinstance(self.implementation_artifacts, tuple)
            or len(self.implementation_artifacts) > 32
            or len(set(self.implementation_artifacts)) != len(self.implementation_artifacts)
            or any(
                not isinstance(path, str)
                or not path
                or len(path) > 4096
                or "\x00" in path
                or "\n" in path
                or not os.path.isabs(path)
                for path in self.implementation_artifacts
            )
        ):
            raise ValueError(
                "signature verifier implementation artifacts must be unique absolute paths"
            )


class ExternalSignatureVerifier:
    """A shell-free, timeout- and output-bounded JSON verifier protocol."""

    production_capable = True

    def __init__(
        self,
        config: ExternalVerifierConfig,
        *,
        working_directory: str | None = None,
    ):
        if not isinstance(config, ExternalVerifierConfig):
            raise TypeError("external verifier config is invalid")
        if working_directory is not None and (
            not isinstance(working_directory, str) or not os.path.isabs(working_directory)
        ):
            raise ValueError("external verifier working directory must be absolute")
        object.__setattr__(self, "_config", config)
        object.__setattr__(self, "_working_directory", working_directory)

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"config", "_config", "_working_directory"} and hasattr(self, "_config"):
            raise AttributeError("external verifier configuration is immutable")
        object.__setattr__(self, name, value)

    @property
    def config(self) -> ExternalVerifierConfig:
        return self._config

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
        if len(payload) > self.config.maximum_input_bytes:
            raise SignatureVerifierError(
                "oversized_input", "signature verifier input exceeded its bound"
            )
        deadline = time.monotonic() + float(self.config.timeout_seconds)
        try:
            process = subprocess.Popen(
                self.config.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                cwd=self._working_directory,
            )
        except OSError as exc:
            raise SignatureVerifierError(
                "unavailable", "signature verifier is unavailable"
            ) from exc
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            selected = selectors.DefaultSelector()
            output = bytearray()
            try:
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                os.set_blocking(process.stderr.fileno(), False)
                selected.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                selected.register(process.stdout, selectors.EVENT_READ, "stdout")
                selected.register(process.stderr, selectors.EVENT_READ, "stderr")
                total = 0
                input_offset = 0
                while selected.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._terminate(process)
                        raise SignatureVerifierError(
                            "timeout", "signature verifier exceeded its timeout"
                        )
                    events = selected.select(min(remaining, 0.1))
                    for key, _mask in events:
                        if key.data == "stdin":
                            try:
                                written = os.write(
                                    key.fileobj.fileno(),
                                    payload[input_offset : input_offset + 65536],
                                )
                            except (BlockingIOError, InterruptedError):
                                continue
                            except BrokenPipeError:
                                written = 0
                                input_offset = len(payload)
                            else:
                                input_offset += written
                            if input_offset >= len(payload) or written == 0:
                                selected.unregister(key.fileobj)
                                key.fileobj.close()
                            continue
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
                raise SignatureVerifierError("timeout", "signature verifier exceeded its timeout")
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
            if not process.stdin.closed:
                process.stdin.close()
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
            raise SignatureVerifierError("preflight_failed", "signature verifier preflight failed")

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
            raise SignatureVerifierError("invalid_verdict", "signature verifier verdict is invalid")
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
    production_admission: bool
    _capability: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.manifest, WorkloadManifest)
            or self.admission_mode not in {"enforced", "development_bypass"}
            or not isinstance(self.production_admission, bool)
            or not isinstance(self._capability, str)
            or re.fullmatch(r"admission-hmac-sha256:[0-9a-f]{64}", self._capability) is None
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
    execution_id: str
    status: str
    provider_job_id: str
    provider_receipt_digest: str

    def __post_init__(self) -> None:
        _validate_digest(self.manifest_digest, "execution manifest digest")
        if (
            not isinstance(self.execution_id, str)
            or _EXECUTION_ID_RE.fullmatch(self.execution_id) is None
        ):
            raise WorkloadAdmissionError("execution_failed", "execution id is invalid")
        if self.status not in {"accepted", "completed"}:
            raise WorkloadAdmissionError("execution_failed", "execution result is invalid")
        if (
            not isinstance(self.provider_job_id, str)
            or _PROVIDER_JOB_ID_RE.fullmatch(self.provider_job_id) is None
        ):
            raise WorkloadAdmissionError("execution_failed", "provider job id is invalid")
        _validate_digest(self.provider_receipt_digest, "provider receipt digest")


@dataclass(frozen=True)
class ExecutionAuthorization:
    """Short-lived authority permit for one exact provider dispatch."""

    execution_id: str
    manifest_digest: str
    policy_digest: str
    configuration_digest: str
    worker_hotkey: str
    production_admission: bool
    issued_at_epoch: int
    expires_at_epoch: int
    capability: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.execution_id, str)
            or _EXECUTION_ID_RE.fullmatch(self.execution_id) is None
        ):
            raise WorkloadAdmissionError(
                "execution_denied", "execution authorization id is invalid"
            )
        _validate_digest(self.manifest_digest, "execution authorization manifest digest")
        _validate_digest(self.policy_digest, "execution authorization policy digest")
        _validate_digest(
            self.configuration_digest,
            "execution authorization configuration digest",
        )
        _validate_identity(self.worker_hotkey, "execution authorization worker")
        if not isinstance(self.production_admission, bool):
            raise WorkloadAdmissionError(
                "execution_denied", "execution authorization provenance is invalid"
            )
        if (
            isinstance(self.issued_at_epoch, bool)
            or not isinstance(self.issued_at_epoch, int)
            or isinstance(self.expires_at_epoch, bool)
            or not isinstance(self.expires_at_epoch, int)
            or not 0 <= self.issued_at_epoch < self.expires_at_epoch
            or self.expires_at_epoch - self.issued_at_epoch > 60
        ):
            raise WorkloadAdmissionError(
                "execution_denied", "execution authorization lifetime is invalid"
            )
        if (
            not isinstance(self.capability, str)
            or _EXECUTION_AUTHORIZATION_RE.fullmatch(self.capability) is None
        ):
            raise WorkloadAdmissionError(
                "execution_denied", "execution authorization capability is invalid"
            )

    def document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "configuration_digest": self.configuration_digest,
                "execution_id": self.execution_id,
                "expires_at_epoch": self.expires_at_epoch,
                "issued_at_epoch": self.issued_at_epoch,
                "manifest_digest": self.manifest_digest,
                "policy_digest": self.policy_digest,
                "production_admission": self.production_admission,
                "schema": EXECUTION_AUTHORIZATION_SCHEMA,
                "worker_hotkey": self.worker_hotkey,
            }
        )

    def wire_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                **self.document(),
                "capability": self.capability,
            }
        )


def _execution_authorization_capability(
    key: bytes,
    authorization: ExecutionAuthorization,
) -> str:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("execution authorization key must contain at least 32 bytes")
    value = hmac.new(
        key,
        b"cathedral-execution-authorization-v1\0"
        + _canonical_json(authorization.document()),
        hashlib.sha256,
    ).hexdigest()
    return "execution-hmac-sha256:" + value


class WorkloadExecutionAdapter(Protocol):
    production_capable: bool

    def _execute_authorized(
        self,
        workload: AdmittedWorkload,
        *,
        execution_id: str,
        authorization: ExecutionAuthorization | None = None,
    ) -> WorkloadExecutionResult: ...


class RecordingExecutionAdapter:
    """Safe local adapter: records admitted manifests and executes no process."""

    production_capable = False

    def __init__(self) -> None:
        self.workloads: list[tuple[str, AdmittedWorkload]] = []

    def _execute_authorized(
        self,
        workload: AdmittedWorkload,
        *,
        execution_id: str,
        authorization: ExecutionAuthorization | None = None,
    ) -> WorkloadExecutionResult:
        if not isinstance(workload, AdmittedWorkload):
            raise WorkloadAdmissionError(
                "execution_denied", "execution requires an admitted workload"
            )
        if not isinstance(execution_id, str) or _EXECUTION_ID_RE.fullmatch(execution_id) is None:
            raise WorkloadAdmissionError("execution_denied", "execution id is invalid")
        self.workloads.append((execution_id, workload))
        provider_job_id = "provider-job-" + hashlib.sha256(
            b"cathedral-recording-adapter-v1\0" + execution_id.encode("ascii")
        ).hexdigest()
        provider_receipt_digest = _sha256(
            b"cathedral-recording-adapter-receipt-v1\0"
            + execution_id.encode("ascii")
            + b"\0"
            + workload.manifest_digest.encode("ascii")
        )
        return WorkloadExecutionResult(
            workload.manifest_digest,
            execution_id,
            "accepted",
            provider_job_id,
            provider_receipt_digest,
        )


@dataclass(frozen=True)
class ExternalExecutionConfig:
    """Pinned local socket contract for a supervised CVM host agent."""

    socket_path: str
    state_path: str
    expected_peer_uid: int
    authorization_key: bytes = field(repr=False)
    worker_hotkey: str
    resource_profiles: tuple[str, ...]
    runtime_profiles: tuple[str, ...]
    configuration_digest: str = field(init=False)
    timeout_seconds: float = 30.0
    maximum_output_bytes: int = 64 * 1024
    maximum_input_bytes: int = DEFAULT_VERIFIER_INPUT_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.authorization_key, bytes) or len(self.authorization_key) < 32:
            raise ValueError(
                "execution authorization key must contain at least 32 bytes"
            )
        _validate_identity(self.worker_hotkey, "execution worker hotkey")
        if (
            not isinstance(self.socket_path, str)
            or not os.path.isabs(self.socket_path)
            or not 1 <= len(self.socket_path) <= 4096
            or "\x00" in self.socket_path
            or "\n" in self.socket_path
        ):
            raise ValueError("execution provider socket path is invalid")
        if (
            not isinstance(self.state_path, str)
            or not os.path.isabs(self.state_path)
            or not 1 <= len(self.state_path) <= 4096
            or "\x00" in self.state_path
            or "\n" in self.state_path
            or self.state_path == self.socket_path
        ):
            raise ValueError("execution provider state path is invalid")
        if (
            isinstance(self.expected_peer_uid, bool)
            or not isinstance(self.expected_peer_uid, int)
            or not 0 <= self.expected_peer_uid <= 2**32 - 1
        ):
            raise ValueError("execution provider peer uid is invalid")
        for name, values in (
            ("execution resource profiles", self.resource_profiles),
            ("execution runtime profiles", self.runtime_profiles),
        ):
            if (
                not isinstance(values, tuple)
                or not values
                or len(values) > 64
                or tuple(sorted(values)) != values
                or len(set(values)) != len(values)
            ):
                raise ValueError(f"{name} must be a sorted unique tuple")
            for value in values:
                _validate_id(value, name)
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 60
        ):
            raise ValueError("execution provider timeout must be between 0 and 60 seconds")
        if (
            isinstance(self.maximum_output_bytes, bool)
            or not isinstance(self.maximum_output_bytes, int)
            or not 256 <= self.maximum_output_bytes <= MAX_VERIFIER_OUTPUT_BYTES
        ):
            raise ValueError("execution provider output bound is invalid")
        if (
            isinstance(self.maximum_input_bytes, bool)
            or not isinstance(self.maximum_input_bytes, int)
            or not 256 <= self.maximum_input_bytes <= MAX_VERIFIER_INPUT_BYTES
        ):
            raise ValueError("execution provider input bound is invalid")
        authorization_key_digest = _sha256(
            b"cathedral-execution-authorization-key-v1\0" + self.authorization_key
        )
        object.__setattr__(
            self,
            "configuration_digest",
            _sha256(
                _canonical_json(
                    {
                        "authorization_key_digest": authorization_key_digest,
                        "expected_peer_uid": self.expected_peer_uid,
                        "maximum_input_bytes": self.maximum_input_bytes,
                        "maximum_output_bytes": self.maximum_output_bytes,
                        "resource_profiles": list(self.resource_profiles),
                        "runtime_profiles": list(self.runtime_profiles),
                        "schema": "cathedral_execution_adapter_configuration_v1",
                        "socket_path": self.socket_path,
                        "state_path": self.state_path,
                        "timeout_seconds": float(self.timeout_seconds),
                        "worker_hotkey": self.worker_hotkey,
                    }
                )
            ),
        )


class ExternalExecutionAdapter:
    """Production-capable adapter for a supervised local CVM host agent.

    The host agent is a declared trust boundary and runs as a separately
    supervised service. Requests use a bounded canonical-JSON frame over a
    permission- and owner-pinned Unix socket, so a request timeout never leaves
    an adapter subprocess behind. Execution IDs are durably bound to one exact
    request before the provider is invoked.
    """

    def __setattr__(self, name: str, value: object) -> None:
        if self.__dict__.get("_configuration_locked", False) and name in {
            "_config",
            "_configuration_locked",
            "_preflight_complete",
            "_production_ready",
            "_state_lock",
            "_authorization_clock",
            "_authorization_clock_lock",
            "_last_authorization_time",
        }:
            raise AttributeError("external execution adapter configuration is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        config: ExternalExecutionConfig,
        *,
        working_directory: str | None = None,
        authorization_clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(config, ExternalExecutionConfig):
            raise TypeError("external execution config is invalid")
        self._configuration_locked = False
        self._config = config
        if working_directory is not None:
            raise ValueError("execution socket adapter does not use a working directory")
        if not callable(authorization_clock):
            raise TypeError("execution authorization clock must be callable")
        self._state_lock = threading.Lock()
        self._authorization_clock = authorization_clock
        self._authorization_clock_lock = threading.Lock()
        self._last_authorization_time: float | None = None
        self._preflight_complete = False
        self._production_ready = False
        self._initialize_state()
        self.startup_preflight()
        object.__setattr__(self, "_production_ready", True)
        object.__setattr__(self, "_configuration_locked", True)

    @property
    def config(self) -> ExternalExecutionConfig:
        return self._config

    @property
    def production_capable(self) -> bool:
        return self._production_ready

    def _authorization_now(self) -> float:
        with self._authorization_clock_lock:
            value = self._authorization_clock()
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                or (
                    self._last_authorization_time is not None
                    and value < self._last_authorization_time
                )
            ):
                raise WorkloadAdmissionError(
                    "execution_denied", "execution authorization clock is invalid"
                )
            sampled = float(value)
            sampled_ms = int(sampled * 1000)
            capability = hmac.new(
                self.config.authorization_key,
                b"cathedral-execution-clock-high-water-v1\0"
                + self.config.configuration_digest.encode("ascii")
                + b"\0"
                + str(sampled_ms).encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            try:
                connection = self._connect_state()
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        """
                        SELECT high_water_ms, capability
                        FROM workload_execution_clock_v1
                        WHERE configuration_digest = ?
                        """,
                        (self.config.configuration_digest,),
                    ).fetchone()
                    if row is not None:
                        persisted_ms = row["high_water_ms"]
                        persisted_capability = row["capability"]
                        if (
                            isinstance(persisted_ms, bool)
                            or not isinstance(persisted_ms, int)
                            or not isinstance(persisted_capability, str)
                        ):
                            connection.execute("ROLLBACK")
                            raise WorkloadAdmissionError(
                                "execution_denied",
                                "execution authorization clock state is invalid",
                            )
                        expected = hmac.new(
                            self.config.authorization_key,
                            b"cathedral-execution-clock-high-water-v1\0"
                            + self.config.configuration_digest.encode("ascii")
                            + b"\0"
                            + str(persisted_ms).encode("ascii"),
                            hashlib.sha256,
                        ).hexdigest()
                        if not hmac.compare_digest(persisted_capability, expected):
                            connection.execute("ROLLBACK")
                            raise WorkloadAdmissionError(
                                "execution_denied",
                                "execution authorization clock state is invalid",
                            )
                        if sampled_ms < persisted_ms:
                            connection.execute("ROLLBACK")
                            raise WorkloadAdmissionError(
                                "execution_denied",
                                "execution authorization clock moved backwards",
                            )
                    connection.execute(
                        """
                        INSERT INTO workload_execution_clock_v1 (
                            configuration_digest, high_water_ms, capability
                        ) VALUES (?, ?, ?)
                        ON CONFLICT(configuration_digest) DO UPDATE SET
                            high_water_ms = excluded.high_water_ms,
                            capability = excluded.capability
                        """,
                        (self.config.configuration_digest, sampled_ms, capability),
                    )
                    connection.execute("COMMIT")
                finally:
                    connection.close()
            except WorkloadAdmissionError:
                raise
            except sqlite3.Error as exc:
                raise WorkloadAdmissionError(
                    "execution_denied", "execution authorization clock is unavailable"
                ) from exc
            object.__setattr__(self, "_last_authorization_time", sampled)
            return sampled

    def _verify_authorization(
        self,
        authorization: ExecutionAuthorization | None,
        workload: AdmittedWorkload,
        execution_id: str,
    ) -> None:
        if not isinstance(authorization, ExecutionAuthorization):
            raise WorkloadAdmissionError(
                "execution_denied", "execution provider requires an authority permit"
            )
        manifest = workload.manifest
        if (
            authorization.execution_id != execution_id
            or authorization.manifest_digest != manifest.digest
            or authorization.policy_digest != manifest.policy_digest
            or authorization.configuration_digest != self.config.configuration_digest
            or authorization.worker_hotkey != self.config.worker_hotkey
            or authorization.production_admission != workload.production_admission
        ):
            raise WorkloadAdmissionError(
                "execution_denied", "execution authority permit binding is invalid"
            )
        expected = _execution_authorization_capability(
            self.config.authorization_key,
            authorization,
        )
        if not hmac.compare_digest(authorization.capability, expected):
            raise WorkloadAdmissionError(
                "execution_denied", "execution authority permit is invalid"
            )
        now = self._authorization_now()
        if not authorization.issued_at_epoch <= now < authorization.expires_at_epoch:
            raise WorkloadAdmissionError(
                "execution_denied", "execution authority permit is expired"
            )

    @staticmethod
    def _parse_document(data: bytes) -> dict[str, object]:
        try:
            return _parse_verifier_document(data)
        except SignatureVerifierError as exc:
            raise ExecutionAdapterError(
                exc.category, "execution provider response is invalid"
            ) from exc

    def _connect_state(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.config.state_path,
            timeout=float(self.config.timeout_seconds),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def _state_identity(self, *, allow_missing: bool) -> tuple[int, int, int, int] | None:
        parent_path = str(Path(self.config.state_path).parent)
        try:
            parent = os.lstat(parent_path)
        except OSError as exc:
            raise ExecutionAdapterError(
                "state_unavailable", "execution state directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o022 != 0
        ):
            raise ExecutionAdapterError(
                "state_unavailable", "execution state directory identity is invalid"
            )
        try:
            metadata = os.lstat(self.config.state_path)
        except FileNotFoundError:
            if allow_missing:
                return None
            raise ExecutionAdapterError(
                "state_unavailable", "execution state is unavailable"
            ) from None
        except OSError as exc:
            raise ExecutionAdapterError(
                "state_unavailable", "execution state is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077 != 0
        ):
            raise ExecutionAdapterError(
                "state_unavailable", "execution state identity is invalid"
            )
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
        )

    def _initialize_state(self) -> None:
        existing = self._state_identity(allow_missing=True)
        try:
            if existing is None:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.config.state_path, flags, 0o600)
                os.close(descriptor)
            before = self._state_identity(allow_missing=False)
            connection = self._connect_state()
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("PRAGMA temp_store = MEMORY")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS workload_execution_bindings_v1 (
                        execution_id TEXT PRIMARY KEY,
                        manifest_digest TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        result_json BLOB,
                        claim_token TEXT,
                        claim_until REAL
                    )
                    """
                )
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(workload_execution_bindings_v1)"
                    )
                }
                if "claim_token" not in columns:
                    connection.execute(
                        "ALTER TABLE workload_execution_bindings_v1 "
                        "ADD COLUMN claim_token TEXT"
                    )
                if "claim_until" not in columns:
                    connection.execute(
                        "ALTER TABLE workload_execution_bindings_v1 "
                        "ADD COLUMN claim_until REAL"
                    )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS workload_execution_clock_v1 (
                        configuration_digest TEXT PRIMARY KEY,
                        high_water_ms INTEGER NOT NULL,
                        capability TEXT NOT NULL
                    )
                    """
                )
            finally:
                connection.close()
            after = self._state_identity(allow_missing=False)
            if after != before:
                raise ExecutionAdapterError(
                    "state_unavailable", "execution state changed during initialization"
                )
        except ExecutionAdapterError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ExecutionAdapterError(
                "state_unavailable", "execution state is unavailable"
            ) from exc

    def _socket_identity(self) -> tuple[int, int, int, int]:
        try:
            parent = os.lstat(str(Path(self.config.socket_path).parent))
            metadata = os.lstat(self.config.socket_path)
        except OSError as exc:
            raise ExecutionAdapterError(
                "unavailable", "execution provider socket is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(parent.st_mode)
            or not stat.S_ISSOCK(metadata.st_mode)
            or parent.st_uid != self.config.expected_peer_uid
            or metadata.st_uid != self.config.expected_peer_uid
            or parent.st_mode & 0o022 != 0
            or metadata.st_mode & 0o022 != 0
        ):
            raise ExecutionAdapterError(
                "unavailable", "execution provider socket identity is invalid"
            )
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
        )

    def _verify_peer(self, connection: socket.socket) -> None:
        if hasattr(socket, "SO_PEERCRED"):
            try:
                raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _pid, uid, _gid = struct.unpack("3i", raw)
            except (OSError, struct.error) as exc:
                raise ExecutionAdapterError(
                    "unavailable", "execution provider peer identity is unavailable"
                ) from exc
            if uid != self.config.expected_peer_uid:
                raise ExecutionAdapterError(
                    "unavailable", "execution provider peer identity is invalid"
                )

    def _invoke(
        self,
        document: Mapping[str, object],
        *,
        authorization: ExecutionAuthorization | None = None,
    ) -> dict[str, object]:
        if document.get("schema") == EXECUTION_REQUEST_SCHEMA:
            if (
                not isinstance(authorization, ExecutionAuthorization)
                or document.get("execution_authorization")
                != dict(authorization.wire_document())
            ):
                raise WorkloadAdmissionError(
                    "execution_denied",
                    "execution transport requires a provider-verifiable permit",
                )
        elif authorization is not None:
            raise WorkloadAdmissionError(
                "execution_denied", "execution permit is invalid for this request"
            )
        payload = _canonical_json(document)
        if len(payload) > self.config.maximum_input_bytes:
            raise ExecutionAdapterError(
                "oversized_input", "execution provider input exceeded its bound"
            )
        before = self._socket_identity()
        deadline = time.monotonic() + float(self.config.timeout_seconds)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(float(self.config.timeout_seconds))
            connection.connect(self.config.socket_path)
            self._verify_peer(connection)
            after = self._socket_identity()
            if after != before:
                raise ExecutionAdapterError(
                    "unavailable", "execution provider socket changed during connection"
                )
            connection.sendall(struct.pack(">I", len(payload)) + payload)
            header = self._receive_exact(connection, 4, deadline)
            response_size = struct.unpack(">I", header)[0]
            if not 1 <= response_size <= self.config.maximum_output_bytes:
                raise ExecutionAdapterError(
                    "oversized_output", "execution provider output exceeded its bound"
                )
            response = self._receive_exact(connection, response_size, deadline)
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            if connection.recv(1) != b"":
                raise ExecutionAdapterError(
                    "malformed_output", "execution provider returned trailing data"
                )
            return self._parse_document(response)
        except ExecutionAdapterError:
            raise
        except (OSError, TimeoutError, struct.error) as exc:
            category = "timeout" if time.monotonic() >= deadline else "unavailable"
            raise ExecutionAdapterError(
                category, "execution provider request failed"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _receive_exact(
        connection: socket.socket,
        size: int,
        deadline: float,
    ) -> bytes:
        output = bytearray()
        while len(output) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ExecutionAdapterError(
                    "timeout", "execution provider exceeded its timeout"
                )
            connection.settimeout(remaining)
            try:
                chunk = connection.recv(size - len(output))
            except socket.timeout as exc:
                raise ExecutionAdapterError(
                    "timeout", "execution provider exceeded its timeout"
                ) from exc
            if not chunk:
                raise ExecutionAdapterError(
                    "malformed_output", "execution provider response was truncated"
                )
            output.extend(chunk)
        return bytes(output)

    def startup_preflight(self) -> None:
        document = self._invoke(
            {
                "configuration_digest": self.config.configuration_digest,
                "resource_profiles": list(self.config.resource_profiles),
                "runtime_profiles": list(self.config.runtime_profiles),
                "schema": EXECUTION_PREFLIGHT_SCHEMA,
                "worker_hotkey": self.config.worker_hotkey,
            }
        )
        expected = {
            "configuration_digest",
            "durable_idempotency",
            "execution_authorization_verification",
            "immutable_manifest_execution",
            "manifest_binding",
            "no_default_credentials",
            "no_host_integration",
            "no_host_network",
            "no_privileged_mode",
            "protocol_version",
            "resource_profiles",
            "runtime_profiles",
            "schema",
            "status",
            "worker_hotkey",
        }
        if (
            set(document) != expected
            or document.get("schema") != EXECUTION_PREFLIGHT_RESULT_SCHEMA
            or document.get("status") != "ready"
            or type(document.get("protocol_version")) is not int
            or document.get("protocol_version") != 1
            or document.get("configuration_digest") != self.config.configuration_digest
            or document.get("worker_hotkey") != self.config.worker_hotkey
            or document.get("resource_profiles") != list(self.config.resource_profiles)
            or document.get("runtime_profiles") != list(self.config.runtime_profiles)
            or any(
                document.get(name) is not True
                for name in (
                    "durable_idempotency",
                    "execution_authorization_verification",
                    "immutable_manifest_execution",
                    "manifest_binding",
                    "no_default_credentials",
                    "no_host_integration",
                    "no_host_network",
                    "no_privileged_mode",
                )
            )
        ):
            raise ExecutionAdapterError(
                "preflight_failed", "execution provider preflight failed"
            )
        object.__setattr__(self, "_preflight_complete", True)

    @staticmethod
    def _result_from_document(
        document: Mapping[str, object],
        *,
        configuration_digest: str,
        execution_id: str,
        manifest_digest: str,
        worker_hotkey: str,
    ) -> WorkloadExecutionResult:
        expected = {
            "configuration_digest",
            "execution_id",
            "manifest_digest",
            "provider_job_id",
            "provider_receipt_digest",
            "schema",
            "status",
            "worker_hotkey",
        }
        if (
            set(document) != expected
            or document.get("schema") != EXECUTION_RESULT_SCHEMA
            or document.get("configuration_digest") != configuration_digest
            or document.get("execution_id") != execution_id
            or document.get("manifest_digest") != manifest_digest
            or document.get("worker_hotkey") != worker_hotkey
        ):
            raise ExecutionAdapterError(
                "invalid_result", "execution provider result binding is invalid"
            )
        try:
            return WorkloadExecutionResult(
                manifest_digest=document["manifest_digest"],  # type: ignore[arg-type]
                execution_id=document["execution_id"],  # type: ignore[arg-type]
                status=document["status"],  # type: ignore[arg-type]
                provider_job_id=document["provider_job_id"],  # type: ignore[arg-type]
                provider_receipt_digest=document["provider_receipt_digest"],  # type: ignore[arg-type]
            )
        except (KeyError, WorkloadAdmissionError) as exc:
            raise ExecutionAdapterError(
                "invalid_result", "execution provider result is invalid"
            ) from exc

    def _execute_authorized(
        self,
        workload: AdmittedWorkload,
        *,
        execution_id: str,
        authorization: ExecutionAuthorization | None = None,
    ) -> WorkloadExecutionResult:
        if not isinstance(workload, AdmittedWorkload):
            raise WorkloadAdmissionError(
                "execution_denied", "execution requires an admitted workload"
            )
        if not isinstance(execution_id, str) or _EXECUTION_ID_RE.fullmatch(execution_id) is None:
            raise WorkloadAdmissionError("execution_denied", "execution id is invalid")
        self._verify_authorization(authorization, workload, execution_id)
        if not self._preflight_complete:
            raise ExecutionAdapterError(
                "preflight_failed", "execution provider preflight is incomplete"
            )
        manifest = workload.manifest
        if (
            manifest.resource_profile not in self.config.resource_profiles
            or manifest.runtime_profile not in self.config.runtime_profiles
            or any(
                (
                    manifest.default_service_credentials,
                    manifest.host_integration,
                    manifest.host_network,
                    manifest.privileged,
                )
            )
        ):
            raise WorkloadAdmissionError(
                "execution_denied", "workload is outside the provider execution profile"
            )
        request = {
            "configuration_digest": self.config.configuration_digest,
            "execution_id": execution_id,
            "manifest": dict(manifest.document()),
            "manifest_digest": manifest.digest,
            "schema": EXECUTION_REQUEST_SCHEMA,
            "worker_hotkey": self.config.worker_hotkey,
        }
        request_digest = _sha256(_canonical_json(request))
        provider_request = {
            **request,
            "execution_authorization": dict(authorization.wire_document()),
        }
        with self._state_lock:
            claim_token = secrets.token_hex(32)
            claim_until = time.time() + float(self.config.timeout_seconds) + 5.0
            try:
                connection = self._connect_state()
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT manifest_digest, request_digest, result_json,
                           claim_token, claim_until
                    FROM workload_execution_bindings_v1
                    WHERE execution_id = ?
                    """,
                    (execution_id,),
                ).fetchone()
                if row is not None and (
                    row["manifest_digest"] != manifest.digest
                    or row["request_digest"] != request_digest
                ):
                    connection.execute("ROLLBACK")
                    raise ExecutionAdapterError(
                        "idempotency_conflict",
                        "execution id was reused with different bindings",
                    )
                if row is not None and row["result_json"] is not None:
                    cached = self._parse_document(bytes(row["result_json"]))
                    result = self._result_from_document(
                        cached,
                        configuration_digest=self.config.configuration_digest,
                        execution_id=execution_id,
                        manifest_digest=manifest.digest,
                        worker_hotkey=self.config.worker_hotkey,
                    )
                    connection.execute("COMMIT")
                    return result
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO workload_execution_bindings_v1 (
                            execution_id, manifest_digest, request_digest, result_json,
                            claim_token, claim_until
                        ) VALUES (?, ?, ?, NULL, ?, ?)
                        """,
                        (
                            execution_id,
                            manifest.digest,
                            request_digest,
                            claim_token,
                            claim_until,
                        ),
                    )
                else:
                    active_claim = row["claim_token"]
                    active_until = row["claim_until"]
                    if (
                        active_claim is not None
                        and isinstance(active_until, (int, float))
                        and float(active_until) > time.time()
                    ):
                        connection.execute("ROLLBACK")
                        raise ExecutionAdapterError(
                            "in_progress", "execution request is already in progress"
                        )
                    connection.execute(
                        """
                        UPDATE workload_execution_bindings_v1
                        SET claim_token = ?, claim_until = ?
                        WHERE execution_id = ? AND request_digest = ?
                        """,
                        (claim_token, claim_until, execution_id, request_digest),
                    )
                connection.execute("COMMIT")
                connection.close()
                del connection

                try:
                    document = self._invoke(
                        provider_request,
                        authorization=authorization,
                    )
                    result = self._result_from_document(
                        document,
                        configuration_digest=self.config.configuration_digest,
                        execution_id=execution_id,
                        manifest_digest=manifest.digest,
                        worker_hotkey=self.config.worker_hotkey,
                    )
                    canonical_result = _canonical_json(document)
                except ExecutionAdapterError:
                    try:
                        release = self._connect_state()
                        try:
                            release.execute("BEGIN IMMEDIATE")
                            release.execute(
                                """
                                UPDATE workload_execution_bindings_v1
                                SET claim_token = NULL, claim_until = NULL
                                WHERE execution_id = ? AND request_digest = ?
                                  AND claim_token = ? AND result_json IS NULL
                                """,
                                (execution_id, request_digest, claim_token),
                            )
                            release.execute("COMMIT")
                        finally:
                            release.close()
                    except sqlite3.Error as exc:
                        raise ExecutionAdapterError(
                            "state_unavailable",
                            "execution state is unavailable",
                        ) from exc
                    raise

                connection = self._connect_state()
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    """
                    UPDATE workload_execution_bindings_v1
                    SET result_json = ?, claim_token = NULL, claim_until = NULL
                    WHERE execution_id = ? AND request_digest = ? AND claim_token = ?
                    """,
                    (canonical_result, execution_id, request_digest, claim_token),
                )
                if updated.rowcount != 1:
                    connection.execute("ROLLBACK")
                    raise ExecutionAdapterError(
                        "state_unavailable", "execution state claim was lost"
                    )
                connection.execute("COMMIT")
                return result
            except ExecutionAdapterError:
                if "connection" in locals() and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            except sqlite3.Error as exc:
                if "connection" in locals() and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise ExecutionAdapterError(
                    "state_unavailable", "execution state is unavailable"
                ) from exc
            finally:
                if "connection" in locals():
                    connection.close()


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

    def __setattr__(self, name: str, value: object) -> None:
        if self.__dict__.get("_configuration_locked", False) and name in {
            "_LOCKED_SECURITY_CONFIGURATION",
            "_capability_key",
            "_configuration_locked",
            "_preflight_complete",
            "policy",
            "production_mode",
            "verifier",
        }:
            raise AttributeError("workload admission security configuration is immutable")
        object.__setattr__(self, name, value)

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
        self._configuration_locked = False
        if production_mode:
            self.startup_preflight()
        object.__setattr__(self, "_configuration_locked", True)

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
        object.__setattr__(self, "_preflight_complete", True)

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

    def _capability(
        self,
        manifest: WorkloadManifest,
        mode: str,
        production_admission: bool,
    ) -> str:
        environment = b"production" if production_admission else b"development"
        material = (
            b"cathedral-workload-admission-v2\0"
            + mode.encode("ascii")
            + b"\0"
            + environment
            + b"\0"
        )
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
            self.production_mode,
            self._capability(manifest, "enforced", self.production_mode),
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

    def development_bypass(self, request: WorkloadRequest, *, reason: str) -> AdmittedWorkload:
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
            False,
            self._capability(manifest, "development_bypass", False),
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
        *,
        execution_id: str,
    ) -> WorkloadExecutionResult:
        if self.production_mode:
            raise WorkloadAdmissionError(
                "execution_denied",
                "production execution requires an authenticated assignment",
            )
        if type(adapter) is not RecordingExecutionAdapter:
            raise WorkloadAdmissionError(
                "execution_denied",
                "direct execution is limited to the development recording adapter",
            )
        return self._dispatch_authorized(
            workload,
            adapter,
            execution_id=execution_id,
        )

    def _dispatch_authorized(
        self,
        workload: AdmittedWorkload,
        adapter: WorkloadExecutionAdapter,
        *,
        execution_id: str,
        authorization: ExecutionAuthorization | None = None,
    ) -> WorkloadExecutionResult:
        self.validate_admission(workload)
        if not isinstance(execution_id, str) or _EXECUTION_ID_RE.fullmatch(execution_id) is None:
            raise WorkloadAdmissionError("execution_denied", "execution id is invalid")
        if self.production_mode and not execution_id.startswith("assignment-"):
            raise WorkloadAdmissionError(
                "execution_denied", "production execution requires an assignment id"
            )
        if self.production_mode:
            if type(adapter) is not ExternalExecutionAdapter or not adapter.production_capable:
                raise WorkloadAdmissionError(
                    "execution_denied", "production execution adapter is unavailable"
                )
        elif type(adapter) not in {RecordingExecutionAdapter, ExternalExecutionAdapter}:
            raise WorkloadAdmissionError(
                "execution_denied", "execution adapter type is unavailable"
            )
        if type(adapter) is ExternalExecutionAdapter:
            if (
                not isinstance(authorization, ExecutionAuthorization)
                or authorization.execution_id != execution_id
                or authorization.manifest_digest != workload.manifest_digest
                or authorization.policy_digest != workload.manifest.policy_digest
                or authorization.configuration_digest
                != adapter.config.configuration_digest
                or authorization.worker_hotkey != adapter.config.worker_hotkey
                or authorization.production_admission != workload.production_admission
            ):
                raise WorkloadAdmissionError(
                    "execution_denied", "execution authority permit binding is invalid"
                )
        try:
            result = adapter._execute_authorized(
                workload,
                execution_id=execution_id,
                authorization=authorization,
            )
        except ExecutionAdapterError as exc:
            raise WorkloadAdmissionError(
                "execution_failed", "execution provider failed closed"
            ) from exc
        if (
            not isinstance(result, WorkloadExecutionResult)
            or result.manifest_digest != workload.manifest_digest
            or result.execution_id != execution_id
        ):
            raise WorkloadAdmissionError(
                "execution_failed", "execution adapter returned a mismatched result"
            )
        return result

    def validate_admission(
        self,
        workload: AdmittedWorkload,
        *,
        require_enforced: bool | None = None,
        require_production: bool | None = None,
    ) -> WorkloadManifest:
        """Validate a capability for execution or a dependent protected action."""

        if require_enforced is None:
            require_enforced = self.production_mode
        if require_production is None:
            require_production = self.production_mode
        if not isinstance(require_enforced, bool):
            raise TypeError("require_enforced must be a boolean")
        if not isinstance(require_production, bool):
            raise TypeError("require_production must be a boolean")
        if not isinstance(workload, AdmittedWorkload):
            raise WorkloadAdmissionError(
                "execution_denied", "execution requires an admitted workload"
            )
        if require_enforced and workload.admission_mode != "enforced":
            raise WorkloadAdmissionError(
                "execution_denied", "protected action requires enforced admission"
            )
        if require_production and not workload.production_admission:
            raise WorkloadAdmissionError(
                "execution_denied",
                "protected action requires production workload admission",
            )
        expected = self._capability(
            workload.manifest,
            workload.admission_mode,
            workload.production_admission,
        )
        if not hmac.compare_digest(workload._capability, expected):
            raise WorkloadAdmissionError(
                "execution_denied", "workload admission capability is invalid"
            )
        return workload.manifest
