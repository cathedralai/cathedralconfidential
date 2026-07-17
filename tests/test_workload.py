"""Signed, digest-pinned workload admission and execution-boundary tests."""

from __future__ import annotations

import dataclasses
import json
import logging
import sys
import time
from pathlib import Path

import pytest

from cathedral.workload import (
    VERIFIER_PREFLIGHT_RESULT_SCHEMA,
    VERIFIER_PREFLIGHT_SCHEMA,
    VERIFIER_REQUEST_SCHEMA,
    VERIFIER_RESULT_SCHEMA,
    AdmittedWorkload,
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
    WorkloadExecutionResult,
    WorkloadManifest,
    WorkloadRequest,
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

    result = controller.dispatch(admitted, adapter)

    assert result.status == "accepted"
    assert result.manifest_digest == admitted.manifest_digest
    assert adapter.workloads == [admitted]
    assert adapter.workloads[0].manifest.image.canonical == IMAGE


def test_forged_or_tampered_admission_capability_never_reaches_adapter():
    controller = _local_controller()
    adapter = RecordingExecutionAdapter()
    admitted = controller.admit(_request())
    forged = dataclasses.replace(admitted, _capability="admission-hmac-sha256:" + "0" * 64)

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.dispatch(forged, adapter)

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
        second.dispatch(admitted, RecordingExecutionAdapter())


def test_execution_adapter_must_echo_exact_manifest_digest():
    class MismatchedAdapter:
        def execute(self, _workload: AdmittedWorkload) -> WorkloadExecutionResult:
            return WorkloadExecutionResult("sha256:" + "0" * 64, "accepted")

    controller = _local_controller()
    admitted = controller.admit(_request())

    with pytest.raises(WorkloadAdmissionError) as raised:
        controller.dispatch(admitted, MismatchedAdapter())

    assert raised.value.category == "execution_failed"


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
