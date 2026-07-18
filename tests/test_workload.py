"""Signed, digest-pinned workload admission and execution-boundary tests."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import logging
import os
import shutil
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cathedral.key_release import KeyReleaseError, WorkloadAssignmentAuthority
from cathedral.workload import (
    EXECUTION_PREFLIGHT_RESULT_SCHEMA,
    EXECUTION_PREFLIGHT_SCHEMA,
    EXECUTION_REQUEST_SCHEMA,
    EXECUTION_RESULT_SCHEMA,
    VERIFIER_PREFLIGHT_RESULT_SCHEMA,
    VERIFIER_PREFLIGHT_SCHEMA,
    VERIFIER_REQUEST_SCHEMA,
    VERIFIER_RESULT_SCHEMA,
    AdmittedWorkload,
    ExecutionAuthorization,
    ExecutionAdapterError,
    ExternalExecutionAdapter,
    ExternalExecutionConfig,
    ExternalSignatureVerifier,
    ExternalVerifierConfig,
    ImageReference,
    LocalSignatureVerifier,
    RecordingExecutionAdapter,
    SignatureVerdict,
    SignatureVerifierError,
    WorkloadAdmissionController,
    WorkloadAdmissionError,
    WorkloadAdmissionPolicy,
    WorkloadManifest,
    WorkloadRequest,
    _execution_authorization_capability,
)


IMAGE_DIGEST = "sha256:" + "a" * 64
SIGNATURE_DIGEST = "sha256:" + "b" * 64
ARGUMENTS_DIGEST = "sha256:" + "c" * 64
CONFIG_DIGEST = "sha256:" + "d" * 64
ARTIFACT_A = "sha256:" + "e" * 64
ARTIFACT_B = "sha256:" + "f" * 64
IMAGE = f"registry.example.com/cathedral/worker@{IMAGE_DIGEST}"
SIGNER = "sigstore://cathedral/worker-release"
ROOT = "cathedral-workload-root-v1"
EXECUTION_ID = "execution-" + "1" * 64


def _policy(**overrides) -> WorkloadAdmissionPolicy:
    values = {
        "policy_id": "customer-cpu-v1",
        "allowed_registries": frozenset({"registry.example.com"}),
        "allowed_signers": frozenset({SIGNER}),
        "trusted_root_ids": frozenset({ROOT}),
        "allowed_resource_profiles": frozenset({"cpu-small"}),
        "allowed_runtime_profiles": frozenset({"confidential-cpu-v1"}),
    }
    values.update(overrides)
    return WorkloadAdmissionPolicy(**values)


def _request(**overrides) -> WorkloadRequest:
    values = {
        "image_reference": IMAGE,
        "required_signer": SIGNER,
        "arguments_digest": ARGUMENTS_DIGEST,
        "config_digest": CONFIG_DIGEST,
        "resource_profile": "cpu-small",
        "runtime_profile": "confidential-cpu-v1",
        "artifact_digests": (ARTIFACT_B, ARTIFACT_A),
    }
    values.update(overrides)
    return WorkloadRequest(**values)


def _verdict(**overrides) -> SignatureVerdict:
    values = {
        "image_reference": IMAGE,
        "signer_identity": SIGNER,
        "trust_root_id": ROOT,
        "signature_digest": SIGNATURE_DIGEST,
    }
    values.update(overrides)
    return SignatureVerdict(**values)


def _local_controller(
    *,
    policy: WorkloadAdmissionPolicy | None = None,
    verifier: LocalSignatureVerifier | None = None,
    audit_events: list[dict[str, object]] | None = None,
) -> WorkloadAdmissionController:
    if verifier is None:
        verifier = LocalSignatureVerifier({IMAGE: _verdict()})
    sink = None
    if audit_events is not None:
        def record_event(event) -> None:
            audit_events.append(dict(event))

        sink = record_event
    return WorkloadAdmissionController(
        policy or _policy(),
        verifier,
        production_mode=False,
        capability_key=b"k" * 32,
        audit_sink=sink,
    )


def _external_script() -> str:
    return f"""
import json, subprocess, sys, time
request = json.loads(sys.stdin.read())
mode = sys.argv[1]
if mode == "timeout":
    time.sleep(2)
elif mode == "oversized":
    sys.stderr.write("s" * 4096)
elif mode == "malformed":
    sys.stdout.write("{{not-json")
elif mode == "nonzero":
    sys.stderr.write("provider-token=do-not-leak")
    raise SystemExit(7)
elif mode == "child_holds_pipes":
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    raise SystemExit(0)
elif mode == "duplicate_keys":
    sys.stdout.write(
        '{{"protocol_version":1,"protocol_version":1,'
        '"schema":"cathedral_workload_verifier_preflight_result_v1",'
        '"status":"ready","trust_root_ids":["cathedral-workload-root-v1"]}}'
    )
elif request["schema"] == {VERIFIER_PREFLIGHT_SCHEMA!r}:
    roots = request["trusted_root_ids"]
    if mode == "missing_root":
        roots = []
    result = {{
        "protocol_version": 1,
        "schema": {VERIFIER_PREFLIGHT_RESULT_SCHEMA!r},
        "status": "ready",
        "trust_root_ids": roots,
    }}
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
elif request["schema"] == {VERIFIER_REQUEST_SCHEMA!r}:
    result = {{
        "image_reference": request["image_reference"],
        "schema": {VERIFIER_RESULT_SCHEMA!r},
        "signature_digest": {SIGNATURE_DIGEST!r},
        "signer_identity": (
            "sigstore://unexpected/signer"
            if mode == "wrong_signer"
            else request["required_signer"]
        ),
        "status": "verified",
        "trust_root_id": request["trusted_root_ids"][0],
    }}
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
else:
    raise SystemExit(8)
"""


def _external_verifier(
    tmp_path: Path,
    mode: str = "valid",
    *,
    timeout: float = 1,
    maximum_output: int = 4096,
) -> ExternalSignatureVerifier:
    script = tmp_path / f"signature-verifier-{mode}.py"
    script.write_text(_external_script(), encoding="utf-8")
    return ExternalSignatureVerifier(
        ExternalVerifierConfig(
            (str(Path(sys.executable).resolve()), str(script), mode),
            timeout_seconds=timeout,
            maximum_output_bytes=maximum_output,
        )
    )


EXECUTION_CONFIGURATION_DIGEST = "sha256:" + "4" * 64
EXECUTION_AUTHORIZATION_KEY = b"a" * 32
EXECUTION_TIME = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


class _ExecutionProviderServer:
    def __init__(self, mode: str, ordinal: int):
        self.root = Path(tempfile.mkdtemp(prefix="cx-exec-", dir="/tmp"))
        self.root.chmod(0o700)
        self.mode = mode
        self.configuration_digest: str | None = None
        self.socket_path = self.root / f"p{ordinal}.sock"
        self.requests: list[dict[str, object]] = []
        self.accepted_execution_ids: list[str] = []
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        self._socket.listen()
        self._socket.settimeout(0.05)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _receive_exact(connection: socket.socket, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            chunk = connection.recv(size - len(output))
            if not chunk:
                raise RuntimeError("truncated request")
            output.extend(chunk)
        return bytes(output)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except (socket.timeout, OSError):
                continue
            with connection:
                try:
                    size = struct.unpack(">I", self._receive_exact(connection, 4))[0]
                    request = json.loads(self._receive_exact(connection, size))
                    self.requests.append(request)
                    self._respond(connection, request)
                except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                    continue

    def _respond(self, connection: socket.socket, request: dict[str, object]) -> None:
        if self.mode == "timeout":
            time.sleep(2)
            return
        if self.mode == "slow_valid" and request["schema"] == EXECUTION_REQUEST_SCHEMA:
            time.sleep(0.1)
        if self.mode == "oversized":
            connection.sendall(struct.pack(">I", 16 * 1024 * 1024))
            return
        if self.mode == "malformed":
            payload = b"{not-json"
        elif request["schema"] == EXECUTION_PREFLIGHT_SCHEMA:
            result = {
                "configuration_digest": (
                    "sha256:" + "0" * 64
                    if self.mode == "wrong_configuration"
                    else self.configuration_digest
                ),
                "durable_idempotency": self.mode != "unsafe_preflight",
                "execution_authorization_verification": True,
                "immutable_manifest_execution": True,
                "manifest_binding": True,
                "no_default_credentials": True,
                "no_host_integration": True,
                "no_host_network": True,
                "no_privileged_mode": True,
                "protocol_version": 1,
                "resource_profiles": request["resource_profiles"],
                "runtime_profiles": request["runtime_profiles"],
                "schema": EXECUTION_PREFLIGHT_RESULT_SCHEMA,
                "status": "ready",
                "worker_hotkey": request["worker_hotkey"],
            }
            payload = json.dumps(
                result, sort_keys=True, separators=(",", ":")
            ).encode()
        elif request["schema"] == EXECUTION_REQUEST_SCHEMA:
            execution_id = request["execution_id"]
            manifest_digest = request["manifest_digest"]
            canonical_manifest_digest = "sha256:" + hashlib.sha256(
                json.dumps(
                    request["manifest"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            raw_authorization = request.get("execution_authorization")
            if not isinstance(raw_authorization, dict):
                return
            try:
                authorization = ExecutionAuthorization(
                    execution_id=raw_authorization["execution_id"],
                    manifest_digest=raw_authorization["manifest_digest"],
                    policy_digest=raw_authorization["policy_digest"],
                    configuration_digest=raw_authorization["configuration_digest"],
                    worker_hotkey=raw_authorization["worker_hotkey"],
                    production_admission=raw_authorization["production_admission"],
                    issued_at_epoch=raw_authorization["issued_at_epoch"],
                    expires_at_epoch=raw_authorization["expires_at_epoch"],
                    capability=raw_authorization["capability"],
                )
            except (KeyError, WorkloadAdmissionError):
                return
            if (
                set(raw_authorization)
                != {*authorization.document(), "capability"}
                or authorization.execution_id != execution_id
                or authorization.manifest_digest != manifest_digest
                or manifest_digest != canonical_manifest_digest
                or authorization.configuration_digest
                != request["configuration_digest"]
                or authorization.worker_hotkey != request["worker_hotkey"]
                or not authorization.issued_at_epoch
                <= EXECUTION_TIME.timestamp()
                < authorization.expires_at_epoch
                or not hmac.compare_digest(
                    authorization.capability,
                    _execution_authorization_capability(
                        EXECUTION_AUTHORIZATION_KEY,
                        authorization,
                    ),
                )
                or "_capability" in request
                or "_capability" in request["manifest"]
                or "authorization_key" in request
            ):
                return
            self.accepted_execution_ids.append(execution_id)
            result = {
                "configuration_digest": request["configuration_digest"],
                "execution_id": execution_id,
                "manifest_digest": manifest_digest,
                "provider_job_id": "provider-job-"
                + hashlib.sha256(execution_id.encode()).hexdigest(),
                "provider_receipt_digest": "sha256:"
                + hashlib.sha256(
                    (execution_id + "\0" + manifest_digest).encode()
                ).hexdigest(),
                "schema": EXECUTION_RESULT_SCHEMA,
                "status": "accepted",
                "worker_hotkey": request["worker_hotkey"],
            }
            if self.mode == "wrong_manifest":
                result["manifest_digest"] = "sha256:" + "0" * 64
            elif self.mode == "wrong_execution":
                result["execution_id"] = "execution-" + "0" * 64
            elif self.mode == "unknown_field":
                result["unexpected"] = True
            payload = json.dumps(
                result, sort_keys=True, separators=(",", ":")
            ).encode()
        else:
            return
        connection.sendall(struct.pack(">I", len(payload)) + payload)

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=0.2)
        self.socket_path.unlink(missing_ok=True)
        shutil.rmtree(self.root, ignore_errors=True)


_EXECUTION_SERVERS: list[_ExecutionProviderServer] = []


@pytest.fixture(autouse=True)
def _close_execution_provider_servers():
    starting = len(_EXECUTION_SERVERS)
    yield
    for server in _EXECUTION_SERVERS[starting:]:
        server.close()
    del _EXECUTION_SERVERS[starting:]


def _external_execution_adapter(
    tmp_path: Path,
    mode: str = "valid",
    *,
    timeout: float = 1,
    maximum_output: int = 4096,
    state_path: Path | None = None,
    authorization_time: float | None = None,
) -> ExternalExecutionAdapter:
    server = _ExecutionProviderServer(mode, len(_EXECUTION_SERVERS))
    _EXECUTION_SERVERS.append(server)
    config = ExternalExecutionConfig(
        socket_path=str(server.socket_path),
        state_path=str(
            state_path
            or tmp_path / f"execution-state-{len(_EXECUTION_SERVERS)}.sqlite"
        ),
            expected_peer_uid=os.getuid(),
        authorization_key=EXECUTION_AUTHORIZATION_KEY,
        worker_hotkey="worker-hotkey",
        resource_profiles=("cpu-small",),
        runtime_profiles=("confidential-cpu-v1",),
        timeout_seconds=timeout,
        maximum_output_bytes=maximum_output,
    )
    server.configuration_digest = config.configuration_digest
    adapter = ExternalExecutionAdapter(
        config,
        authorization_clock=lambda: (
            EXECUTION_TIME.timestamp()
            if authorization_time is None
            else authorization_time
        ),
    )
    object.__setattr__(adapter, "_test_server", server)
    return adapter


def _external_assignment(
    controller: WorkloadAdmissionController,
    admitted,
    adapter: ExternalExecutionAdapter,
):
    authority = WorkloadAssignmentAuthority(
        controller,
        EXECUTION_AUTHORIZATION_KEY,
        clock=lambda: EXECUTION_TIME,
        execution_worker_hotkey="worker-hotkey",
        execution_configuration_digest=adapter.config.configuration_digest,
    )
    assignment = authority.issue(
        authenticated_issuer_id="customer-account",
        worker_hotkey="worker-hotkey",
        workload=admitted,
        data_key_reference="kms/customer/data-key",
    )
    return authority, assignment


def test_strict_digest_reference_is_canonical():
    image = ImageReference.parse(IMAGE)

    assert image.registry == "registry.example.com"
    assert image.repository == "cathedral/worker"
    assert image.digest == IMAGE_DIGEST
    assert image.canonical == IMAGE


@pytest.mark.parametrize(
    "reference",
    [
        "registry.example.com/cathedral/worker:latest",
        "registry.example.com/cathedral/worker",
        f"docker://registry.example.com/cathedral/worker@{IMAGE_DIGEST}",
        f"https://registry.example.com/cathedral/worker@{IMAGE_DIGEST}",
        f"user:password@registry.example.com/cathedral/worker@{IMAGE_DIGEST}",
        f"registry.example.com/cathedral/../worker@{IMAGE_DIGEST}",
        f"registry.example.com/cathedral//worker@{IMAGE_DIGEST}",
        f"registry.example.com/Cathedral/worker@{IMAGE_DIGEST}",
        f"registry.example.com/cathedral/worker@sha512:{'a' * 128}",
        f"registry.example.com/cathedral/worker@{IMAGE_DIGEST}?tag=latest",
        f"registry.example.com/cathedral/%2e%2e/worker@{IMAGE_DIGEST}",
        f"127.0.0.1/cathedral/worker@{IMAGE_DIGEST}",
        f"localhost/cathedral/worker@{IMAGE_DIGEST}",
        f"registry.example.com:5000/cathedral/worker@{IMAGE_DIGEST}",
    ],
)
def test_strict_parser_rejects_mutable_ambiguous_or_local_references(reference: str):
    with pytest.raises(WorkloadAdmissionError) as raised:
        ImageReference.parse(reference)

    assert raised.value.category == "invalid_image_reference"
    assert "password" not in str(raised.value)


def test_manifest_is_canonical_and_artifact_order_is_stable():
    controller = _local_controller()

    first = controller.admit(_request())
    second = controller.admit(_request(artifact_digests=(ARTIFACT_A, ARTIFACT_B)))

    assert first.manifest.artifact_digests == (ARTIFACT_A, ARTIFACT_B)
    assert first.manifest.canonical_bytes == second.manifest.canonical_bytes
    assert first.manifest_digest == second.manifest_digest
    document = json.loads(first.manifest.canonical_bytes)
    assert document["image_reference"] == IMAGE
    assert document["policy_digest"] == _policy().digest
    assert document["default_service_credentials"] is False
    assert document["host_integration"] is False
    assert document["host_network"] is False
    assert document["privileged"] is False


@pytest.mark.parametrize(
    ("policy", "workload_request", "category"),
    [
        (
            _policy(allowed_registries=frozenset({"other.example.com"})),
            _request(),
            "registry_denied",
        ),
        (
            _policy(allowed_signers=frozenset({"sigstore://other/signer"})),
            _request(),
            "signer_denied",
        ),
        (
            _policy(allowed_resource_profiles=frozenset({"cpu-large"})),
            _request(),
            "resource_denied",
        ),
        (
            _policy(allowed_runtime_profiles=frozenset({"unsafe-runtime"})),
            _request(),
            "runtime_denied",
        ),
    ],
)
def test_policy_denials_happen_before_external_verification(
    policy, workload_request, category
):
    verifier = LocalSignatureVerifier({IMAGE: _verdict()})
    controller = _local_controller(policy=policy, verifier=verifier)

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.admit(workload_request)

    assert raised.value.category == category
    assert verifier.calls == 0


def test_unknown_signer_or_root_cannot_be_substituted_by_verifier():
    class RootSubstitutionVerifier(LocalSignatureVerifier):
        def preflight(self, trusted_root_ids: frozenset[str]) -> None:
            return None

    signer_controller = _local_controller(
        verifier=LocalSignatureVerifier(
            {IMAGE: _verdict(signer_identity="sigstore://unexpected/signer")}
        )
    )
    root_controller = _local_controller(
        verifier=RootSubstitutionVerifier(
            {IMAGE: _verdict(trust_root_id="unexpected-root")}
        )
    )

    with pytest.raises(WorkloadAdmissionError, match="does not match"):
        signer_controller.admit(_request())
    with pytest.raises(WorkloadAdmissionError, match="does not match"):
        root_controller.admit(_request())


def test_production_refuses_local_verifier():
    with pytest.raises(WorkloadAdmissionError) as raised:
        WorkloadAdmissionController(
            _policy(),
            LocalSignatureVerifier({IMAGE: _verdict()}),
            production_mode=True,
        )

    assert raised.value.category == "verifier_unavailable"


@pytest.mark.parametrize(
    "isolation_override",
    [
        {"default_service_credentials": True},
        {"host_integration": True},
        {"host_network": True},
        {"privileged": True},
    ],
)
def test_production_denies_unsafe_runtime_isolation_controls(
    tmp_path: Path, isolation_override: dict[str, bool]
):
    controller = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path),
        production_mode=True,
        capability_key=b"p" * 32,
    )

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.admit(_request(**isolation_override))

    assert raised.value.category == "runtime_denied"


def test_external_verifier_preflight_and_exact_verdict_support_production(tmp_path: Path):
    controller = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path),
        production_mode=True,
        capability_key=b"p" * 32,
    )

    admitted = controller.admit(_request())

    assert admitted.manifest.signer_identity == SIGNER
    assert admitted.manifest.trust_root_id == ROOT
    assert admitted.manifest.signature_digest == SIGNATURE_DIGEST


@pytest.mark.parametrize(
    ("mode", "category"),
    [
        ("timeout", "timeout"),
        ("oversized", "oversized_output"),
        ("malformed", "malformed_output"),
        ("nonzero", "nonzero_exit"),
        ("missing_root", "preflight_failed"),
        ("duplicate_keys", "malformed_output"),
    ],
)
def test_external_verifier_failures_are_bounded_and_secret_safe(
    tmp_path: Path, mode: str, category: str
):
    verifier = _external_verifier(
        tmp_path,
        mode,
        timeout=0.05 if mode == "timeout" else 1,
        maximum_output=256 if mode == "oversized" else 4096,
    )

    with pytest.raises(SignatureVerifierError) as raised:
        verifier.preflight(frozenset({ROOT}))

    assert raised.value.category == category
    assert "provider-token" not in str(raised.value)


def test_child_holding_verifier_pipes_cannot_defeat_timeout(tmp_path: Path):
    verifier = _external_verifier(tmp_path, "child_holds_pipes", timeout=0.1)
    started = time.monotonic()

    with pytest.raises(SignatureVerifierError) as raised:
        verifier.preflight(frozenset({ROOT}))

    assert raised.value.category == "timeout"
    assert time.monotonic() - started < 1


def test_child_not_reading_large_stdin_cannot_defeat_timeout(tmp_path: Path):
    helper = tmp_path / "does-not-read.py"
    helper.write_text("import time; time.sleep(2)\n", encoding="utf-8")
    verifier = ExternalSignatureVerifier(
        ExternalVerifierConfig(
            (str(Path(sys.executable).resolve()), str(helper)),
            timeout_seconds=0.1,
        )
    )
    started = time.monotonic()

    with pytest.raises(SignatureVerifierError) as raised:
        verifier._invoke({"payload": "x" * (4 * 1024 * 1024)})

    assert raised.value.category == "timeout"
    assert time.monotonic() - started < 1


def test_external_verifier_wrong_signer_fails_exact_request_binding(tmp_path: Path):
    controller = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path, "wrong_signer"),
        production_mode=True,
        capability_key=b"p" * 32,
    )

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.admit(_request())

    assert raised.value.category == "signature_denied"


def test_external_command_rejects_credentials_and_relative_executable():
    with pytest.raises(ValueError, match="credential-free"):
        ExternalVerifierConfig(("verifier",))
    with pytest.raises(ValueError, match="credential-free"):
        ExternalVerifierConfig((str(Path(sys.executable).resolve()), "--token=secret"))
    with pytest.raises(ValueError, match="credential-free"):
        ExternalVerifierConfig((str(Path(sys.executable).resolve()), "--token", "secret"))


def test_production_startup_refuses_misconfigured_verifier(tmp_path: Path):
    with pytest.raises(WorkloadAdmissionError) as raised:
        WorkloadAdmissionController(
            _policy(),
            _external_verifier(tmp_path, "missing_root"),
            production_mode=True,
            capability_key=b"p" * 32,
        )

    assert raised.value.category == "verifier_unavailable"


def test_preflight_protocol_version_rejects_boolean_type(tmp_path: Path):
    script = tmp_path / "boolean-version.py"
    script.write_text(
        "import json,sys; r=json.loads(sys.stdin.read()); "
        "print(json.dumps({'protocol_version':True,'schema':"
        f"{VERIFIER_PREFLIGHT_RESULT_SCHEMA!r},'status':'ready',"
        "'trust_root_ids':r['trusted_root_ids']},sort_keys=True,separators=(',',':')))",
        encoding="utf-8",
    )
    verifier = ExternalSignatureVerifier(
        ExternalVerifierConfig(
            (str(Path(sys.executable).resolve()), str(script)),
            maximum_output_bytes=4096,
        )
    )

    with pytest.raises(SignatureVerifierError) as raised:
        verifier.preflight(frozenset({ROOT}))

    assert raised.value.category == "preflight_failed"


def test_audit_only_returns_no_executable_capability_and_records_safe_event():
    events: list[dict[str, object]] = []
    controller = _local_controller(audit_events=events)

    decision = controller.audit(_request())

    assert decision.status == "would_admit"
    assert decision.manifest_digest is not None
    assert not isinstance(decision, AdmittedWorkload)
    assert events[-1] == {
        "category": None,
        "manifest_digest": decision.manifest_digest,
        "policy_digest": _policy().digest,
        "policy_id": "customer-cpu-v1",
        "status": "would_admit",
    }


def test_audit_denial_is_typed_and_does_not_call_adapter():
    controller = _local_controller(
        policy=_policy(allowed_resource_profiles=frozenset({"cpu-large"}))
    )
    adapter = RecordingExecutionAdapter()

    decision = controller.audit(_request())

    assert decision.status == "would_deny"
    assert decision.category == "resource_denied"
    assert adapter.workloads == []


def test_execution_adapter_receives_only_exact_admitted_manifest():
    controller = _local_controller()
    adapter = RecordingExecutionAdapter()
    admitted = controller.admit(_request())

    result = controller.dispatch(admitted, adapter, execution_id=EXECUTION_ID)

    assert result.status == "accepted"
    assert result.manifest_digest == admitted.manifest_digest
    assert result.execution_id == EXECUTION_ID
    assert adapter.workloads == [(EXECUTION_ID, admitted)]
    assert adapter.workloads[0][1].manifest.image.canonical == IMAGE


def test_forged_or_tampered_admission_capability_never_reaches_adapter():
    controller = _local_controller()
    adapter = RecordingExecutionAdapter()
    admitted = controller.admit(_request())
    forged = dataclasses.replace(admitted, _capability="admission-hmac-sha256:" + "0" * 64)

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.dispatch(forged, adapter, execution_id=EXECUTION_ID)

    assert raised.value.category == "execution_denied"
    assert adapter.workloads == []


def test_capability_is_controller_local_and_cannot_cross_authorities():
    first = _local_controller()
    second = WorkloadAdmissionController(
        _policy(),
        LocalSignatureVerifier({IMAGE: _verdict()}),
        production_mode=False,
        capability_key=b"z" * 32,
    )
    admitted = first.admit(_request())

    with pytest.raises(WorkloadAdmissionError, match="capability"):
        second.dispatch(
            admitted,
            RecordingExecutionAdapter(),
            execution_id=EXECUTION_ID,
        )


def test_production_controller_has_no_unassigned_dispatch_path(tmp_path: Path):
    controller = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path),
        production_mode=True,
        capability_key=b"p" * 32,
    )
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(tmp_path)

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.dispatch(admitted, adapter, execution_id=EXECUTION_ID)

    assert raised.value.category == "execution_denied"
    assert len(adapter._test_server.requests) == 1  # startup preflight only
    with pytest.raises(WorkloadAdmissionError) as private_bypass:
        controller._dispatch_authorized(
            admitted,
            adapter,
            execution_id="assignment-" + "0" * 64,
        )
    assert private_bypass.value.category == "execution_denied"
    assert len(adapter._test_server.requests) == 1


def test_production_assignment_is_the_only_external_dispatch_path(tmp_path: Path):
    controller = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path),
        production_mode=True,
        capability_key=b"p" * 32,
    )
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(tmp_path)
    authority = WorkloadAssignmentAuthority(
        controller,
        b"a" * 32,
        clock=lambda: EXECUTION_TIME,
        execution_worker_hotkey="worker-hotkey",
        execution_configuration_digest=adapter.config.configuration_digest,
    )
    assignment = authority.issue(
        authenticated_issuer_id="customer-account",
        worker_hotkey="worker-hotkey",
        workload=admitted,
        data_key_reference="kms/customer/data-key",
    )
    result = authority.dispatch_execution(
        assignment=assignment,
        workload=admitted,
        adapter=adapter,
    )

    assert result.execution_id == assignment.assignment_id
    assert result.manifest_digest == assignment.manifest_digest
    assert len(adapter._test_server.requests) == 2


def test_external_adapter_direct_call_cannot_bypass_controller(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(tmp_path)

    with pytest.raises(WorkloadAdmissionError) as raised:
        adapter._execute_authorized(
            admitted,
            execution_id=EXECUTION_ID,
        )

    assert raised.value.category == "execution_denied"
    assert len(adapter._test_server.requests) == 1


def test_execution_transport_rejects_raw_unauthorized_request(tmp_path: Path):
    adapter = _external_execution_adapter(tmp_path)

    with pytest.raises(WorkloadAdmissionError) as raised:
        adapter._invoke(
            {
                "schema": EXECUTION_REQUEST_SCHEMA,
                "execution_id": EXECUTION_ID,
            }
        )

    assert raised.value.category == "execution_denied"
    assert len(adapter._test_server.requests) == 1


def test_provider_rejects_raw_socket_execution_without_permit(tmp_path: Path):
    adapter = _external_execution_adapter(tmp_path)
    payload = json.dumps(
        {
            "configuration_digest": adapter.config.configuration_digest,
            "execution_id": EXECUTION_ID,
            "manifest": {},
            "manifest_digest": "sha256:" + "0" * 64,
            "schema": EXECUTION_REQUEST_SCHEMA,
            "worker_hotkey": "worker-hotkey",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(adapter.config.socket_path)
        connection.sendall(struct.pack(">I", len(payload)) + payload)
        assert connection.recv(1) == b""

    assert adapter._test_server.accepted_execution_ids == []


def test_forged_execution_authorization_never_reaches_provider(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(tmp_path)
    forged = ExecutionAuthorization(
        execution_id=EXECUTION_ID,
        manifest_digest=admitted.manifest_digest,
        policy_digest=admitted.manifest.policy_digest,
        configuration_digest=adapter.config.configuration_digest,
        worker_hotkey="worker-hotkey",
        production_admission=False,
        issued_at_epoch=int(EXECUTION_TIME.timestamp()),
        expires_at_epoch=int(EXECUTION_TIME.timestamp()) + 30,
        capability="execution-hmac-sha256:" + "0" * 64,
    )

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller._dispatch_authorized(
            admitted,
            adapter,
            execution_id=EXECUTION_ID,
            authorization=forged,
        )

    assert raised.value.category == "execution_denied"
    assert len(adapter._test_server.requests) == 1


def test_execution_authorization_expires_before_provider_call(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(
        tmp_path,
        authorization_time=EXECUTION_TIME.timestamp() + 31,
    )
    authority, assignment = _external_assignment(controller, admitted, adapter)

    with pytest.raises(KeyReleaseError) as raised:
        authority.dispatch_execution(
            assignment=assignment,
            workload=admitted,
            adapter=adapter,
        )

    assert raised.value.category == "execution_failed"
    assert len(adapter._test_server.requests) == 1


def test_execution_clock_rollback_remains_denied_after_adapter_restart(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(
        tmp_path,
        authorization_time=EXECUTION_TIME.timestamp() + 31,
    )
    unsigned = ExecutionAuthorization(
        execution_id=EXECUTION_ID,
        manifest_digest=admitted.manifest_digest,
        policy_digest=admitted.manifest.policy_digest,
        configuration_digest=adapter.config.configuration_digest,
        worker_hotkey="worker-hotkey",
        production_admission=False,
        issued_at_epoch=int(EXECUTION_TIME.timestamp()),
        expires_at_epoch=int(EXECUTION_TIME.timestamp()) + 30,
        capability="execution-hmac-sha256:" + "0" * 64,
    )
    authorization = dataclasses.replace(
        unsigned,
        capability=_execution_authorization_capability(
            EXECUTION_AUTHORIZATION_KEY,
            unsigned,
        ),
    )

    with pytest.raises(WorkloadAdmissionError):
        controller._dispatch_authorized(
            admitted,
            adapter,
            execution_id=EXECUTION_ID,
            authorization=authorization,
        )

    restarted = ExternalExecutionAdapter(
        adapter.config,
        authorization_clock=lambda: EXECUTION_TIME.timestamp() + 1,
    )
    object.__setattr__(restarted, "_test_server", adapter._test_server)
    with pytest.raises(WorkloadAdmissionError) as raised:
        controller._dispatch_authorized(
            admitted,
            restarted,
            execution_id=EXECUTION_ID,
            authorization=authorization,
        )

    assert raised.value.category == "execution_denied"
    execution_requests = [
        request
        for request in adapter._test_server.requests
        if request.get("schema") == EXECUTION_REQUEST_SCHEMA
    ]
    assert execution_requests == []


def test_assignment_is_bound_to_one_provider_configuration(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    trusted_adapter = _external_execution_adapter(tmp_path)
    authority, assignment = _external_assignment(
        controller,
        admitted,
        trusted_adapter,
    )
    adapter = _external_execution_adapter(tmp_path)

    assert adapter.config.configuration_digest != (
        trusted_adapter.config.configuration_digest
    )

    with pytest.raises(KeyReleaseError) as raised:
        authority.dispatch_execution(
            assignment=assignment,
            workload=admitted,
            adapter=adapter,
        )

    assert raised.value.category == "execution_denied"
    assert len(adapter._test_server.requests) == 1


def test_external_adapter_security_configuration_is_immutable(tmp_path: Path):
    adapter = _external_execution_adapter(tmp_path)

    for name, value in (
        ("_config", adapter.config),
        ("_state_lock", adapter._state_lock),
        ("_preflight_complete", False),
        ("_production_ready", False),
    ):
        with pytest.raises(AttributeError):
            setattr(adapter, name, value)


def test_production_refuses_recording_execution_adapter(tmp_path: Path):
    controller = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path),
        production_mode=True,
        capability_key=b"p" * 32,
    )
    admitted = controller.admit(_request())
    authority = WorkloadAssignmentAuthority(
        controller,
        b"a" * 32,
        clock=lambda: datetime(2026, 7, 18, 12, 0, tzinfo=UTC),
        execution_worker_hotkey="worker-hotkey",
        execution_configuration_digest=EXECUTION_CONFIGURATION_DIGEST,
    )
    assignment = authority.issue(
        authenticated_issuer_id="customer-account",
        worker_hotkey="worker-hotkey",
        workload=admitted,
        data_key_reference="kms/customer/data-key",
    )

    with pytest.raises(KeyReleaseError) as raised:
        authority.dispatch_execution(
            assignment=assignment,
            workload=admitted,
            adapter=RecordingExecutionAdapter(),
        )

    assert raised.value.category == "execution_failed"


@pytest.mark.parametrize("mode", ["unsafe_preflight", "wrong_configuration"])
def test_external_execution_preflight_fails_closed(tmp_path: Path, mode: str):
    with pytest.raises(ExecutionAdapterError) as raised:
        _external_execution_adapter(tmp_path, mode)

    assert raised.value.category == "preflight_failed"


@pytest.mark.parametrize("unsafe_kind", ["parent_permissions", "file_permissions", "symlink"])
def test_external_execution_state_identity_fails_closed(
    tmp_path: Path,
    unsafe_kind: str,
):
    state_parent = tmp_path / "state"
    state_parent.mkdir(mode=0o700)
    state_path = state_parent / "execution.sqlite"
    if unsafe_kind == "parent_permissions":
        state_parent.chmod(0o777)
    elif unsafe_kind == "file_permissions":
        state_path.touch(mode=0o644)
    else:
        target = tmp_path / "target.sqlite"
        target.touch(mode=0o600)
        state_path.symlink_to(target)

    with pytest.raises(ExecutionAdapterError) as raised:
        _external_execution_adapter(tmp_path, state_path=state_path)

    assert raised.value.category == "state_unavailable"


@pytest.mark.parametrize(
    "mode",
    ["wrong_manifest", "wrong_execution", "unknown_field"],
)
def test_external_execution_result_must_match_exact_request(
    tmp_path: Path,
    mode: str,
):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(tmp_path, mode)
    authority, assignment = _external_assignment(controller, admitted, adapter)

    with pytest.raises(KeyReleaseError) as raised:
        authority.dispatch_execution(
            assignment=assignment,
            workload=admitted,
            adapter=adapter,
        )

    assert raised.value.category == "execution_failed"


@pytest.mark.parametrize(
    ("mode", "category"),
    [
        ("timeout", "timeout"),
        ("oversized", "oversized_output"),
        ("malformed", "malformed_output"),
    ],
)
def test_external_execution_failures_are_bounded_and_secret_safe(
    tmp_path: Path,
    mode: str,
    category: str,
):
    started = time.monotonic()
    with pytest.raises(ExecutionAdapterError) as raised:
        _external_execution_adapter(
            tmp_path,
            mode,
            timeout=0.05 if mode == "timeout" else 1,
            maximum_output=256 if mode == "oversized" else 4096,
        )

    assert raised.value.category == category
    assert "provider-token" not in str(raised.value)
    assert time.monotonic() - started < 1


def test_external_execution_is_idempotently_bound_to_execution_id(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = _external_execution_adapter(tmp_path)
    authority, assignment = _external_assignment(controller, admitted, adapter)

    first = authority.dispatch_execution(
        assignment=assignment,
        workload=admitted,
        adapter=adapter,
    )
    second = authority.dispatch_execution(
        assignment=assignment,
        workload=admitted,
        adapter=adapter,
    )

    assert first == second
    assert len(adapter._test_server.requests) == 2  # preflight plus one execution


def test_failed_provider_result_keeps_durable_request_binding(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    state_path = tmp_path / "failed-execution-state.sqlite"
    adapter = _external_execution_adapter(
        tmp_path,
        "wrong_manifest",
        state_path=state_path,
    )
    authority, assignment = _external_assignment(controller, admitted, adapter)
    for attempt in (1, 2):
        with pytest.raises(KeyReleaseError):
            authority.dispatch_execution(
                assignment=assignment,
                workload=admitted,
                adapter=adapter,
            )
        with sqlite3.connect(state_path) as connection:
            rows = connection.execute(
                """
                SELECT execution_id, manifest_digest, request_digest,
                       result_json, claim_token, claim_until
                FROM workload_execution_bindings_v1
                """
            ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == assignment.assignment_id
        assert rows[0][1] == admitted.manifest_digest
        assert rows[0][2].startswith("sha256:")
        assert rows[0][3:] == (None, None, None)
        execution_requests = [
            request
            for request in adapter._test_server.requests
            if request.get("schema") == EXECUTION_REQUEST_SCHEMA
        ]
        assert len(execution_requests) == attempt


def test_concurrent_adapters_share_one_durable_execution_claim(tmp_path: Path):
    controller = _local_controller()
    admitted = controller.admit(_request())
    state_path = tmp_path / "concurrent-execution-state.sqlite"
    first_adapter = _external_execution_adapter(
        tmp_path,
        "slow_valid",
        state_path=state_path,
    )
    authority, assignment = _external_assignment(
        controller,
        admitted,
        first_adapter,
    )
    second_adapter = ExternalExecutionAdapter(
        first_adapter.config,
        authorization_clock=lambda: EXECUTION_TIME.timestamp(),
    )
    object.__setattr__(second_adapter, "_test_server", first_adapter._test_server)

    def dispatch(adapter):
        try:
            return authority.dispatch_execution(
                assignment=assignment,
                workload=admitted,
                adapter=adapter,
            )
        except KeyReleaseError as exc:
            return exc.category

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(dispatch, (first_adapter, second_adapter)))

    results = [outcome for outcome in outcomes if not isinstance(outcome, str)]
    assert len(results) == 1
    assert set(outcome for outcome in outcomes if isinstance(outcome, str)) == {
        "execution_failed"
    }
    execution_requests = [
        request
        for request in first_adapter._test_server.requests
        if request.get("schema") == EXECUTION_REQUEST_SCHEMA
    ]
    assert len(execution_requests) == 1

    replay = authority.dispatch_execution(
        assignment=assignment,
        workload=admitted,
        adapter=second_adapter,
    )
    assert replay == results[0]


def test_execution_id_cannot_cross_manifests_or_restart_state(tmp_path: Path):
    controller = _local_controller()
    first_workload = controller.admit(_request())
    second_workload = controller.admit(
        _request(config_digest="sha256:" + "9" * 64)
    )
    state_path = tmp_path / "durable-execution-state.sqlite"
    first_adapter = _external_execution_adapter(tmp_path, state_path=state_path)
    authority, assignment = _external_assignment(
        controller,
        first_workload,
        first_adapter,
    )

    first = authority.dispatch_execution(
        assignment=assignment,
        workload=first_workload,
        adapter=first_adapter,
    )
    restarted = ExternalExecutionAdapter(
        first_adapter.config,
        authorization_clock=lambda: EXECUTION_TIME.timestamp(),
    )
    object.__setattr__(restarted, "_test_server", first_adapter._test_server)
    replay = authority.dispatch_execution(
        assignment=assignment,
        workload=first_workload,
        adapter=restarted,
    )

    assert replay == first
    assert len(restarted._test_server.requests) == 3  # 2 preflights plus 1 execution
    with pytest.raises(KeyReleaseError) as raised:
        authority.dispatch_execution(
            assignment=assignment,
            workload=second_workload,
            adapter=restarted,
        )
    assert raised.value.category == "execution_denied"
    assert len(restarted._test_server.requests) == 3


@pytest.mark.parametrize(
    "execution_id",
    [
        "",
        "execution-short",
        "assignment-" + "A" * 64,
        "provider-job-" + "1" * 64,
    ],
)
def test_invalid_execution_id_never_reaches_adapter(execution_id: str):
    controller = _local_controller()
    admitted = controller.admit(_request())
    adapter = RecordingExecutionAdapter()

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.dispatch(admitted, adapter, execution_id=execution_id)

    assert raised.value.category == "execution_denied"
    assert adapter.workloads == []


def test_development_bypass_is_explicit_logged_and_unavailable_in_production(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
):
    controller = _local_controller()
    with caplog.at_level(logging.WARNING, logger="cathedral.workload"):
        admitted = controller.development_bypass(
            _request(required_signer="sigstore://untrusted/development"),
            reason="local integration fixture",
        )

    assert admitted.admission_mode == "development_bypass"
    assert admitted.manifest.signer_identity == "development-bypass"
    assert "local integration fixture" not in caplog.text
    assert "manifest_digest=" in caplog.text
    assert "reason_digest=sha256:" in caplog.text

    production = WorkloadAdmissionController(
        _policy(),
        _external_verifier(tmp_path),
        production_mode=True,
        capability_key=b"p" * 32,
    )
    with pytest.raises(WorkloadAdmissionError) as raised:
        production.development_bypass(_request(), reason="never")
    assert raised.value.category == "bypass_denied"


def test_later_tag_movement_cannot_change_an_admitted_digest():
    controller = _local_controller()
    admitted = controller.admit(_request())
    original = admitted.manifest_digest

    with pytest.raises(WorkloadAdmissionError):
        controller.admit(
            _request(image_reference="registry.example.com/cathedral/worker:stable")
        )

    assert admitted.manifest.image.digest == IMAGE_DIGEST
    assert admitted.manifest_digest == original


def test_manifest_constructor_rejects_unsorted_or_duplicate_artifacts():
    image = ImageReference.parse(IMAGE)
    values = {
        "image": image,
        "signer_identity": SIGNER,
        "trust_root_id": ROOT,
        "signature_digest": SIGNATURE_DIGEST,
        "policy_id": "customer-cpu-v1",
        "policy_digest": _policy().digest,
        "arguments_digest": ARGUMENTS_DIGEST,
        "config_digest": CONFIG_DIGEST,
        "resource_profile": "cpu-small",
        "runtime_profile": "confidential-cpu-v1",
    }

    with pytest.raises(WorkloadAdmissionError, match="artifacts"):
        WorkloadManifest(**values, artifact_digests=(ARTIFACT_B, ARTIFACT_A))
    with pytest.raises(WorkloadAdmissionError, match="artifacts"):
        WorkloadManifest(**values, artifact_digests=(ARTIFACT_A, ARTIFACT_A))
