"""Versioned REPORT_DATA and live TLS channel-binding contracts."""

from __future__ import annotations

import os
import hashlib
import shutil
import sqlite3
import ssl
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from dataclasses import replace
from pathlib import Path

import pytest

from cathedral.assurance import ClaimStatus, attestation_claims
from cathedral.channel import (
    ChannelBindingError,
    application_key_binding,
    extract_spki_der,
    tls_spki_binding,
)
from cathedral.common import (
    Attested,
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    MAX_EVIDENCE_RESPONSE_BODY,
    Policy,
    Tier,
    report_data_v2,
)
from cathedral.enroll import RegistryStore
from cathedral.gpu import (
    ExternalGpuVerifier,
    GpuAttestationError,
    GpuComponentVerdict,
    GpuDeviceClaim,
    GpuIdentityRegistry,
    GpuProfile,
    gpu_challenge,
    gpu_host_session_digest,
    gpu_identity_policy_digest,
    gpu_profile_authority,
    tdx_component_binding_digest,
)
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.ledger import Ledger
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.runtime import (
    ConfidentialRuntime,
    MinerTarget,
    RuntimeConfig,
    RuntimeError as CathedralRuntimeError,
    _AttestationResult,
)
from cathedral.worker import WorkerServer
from cathedral.workload import ExternalVerifierConfig


HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"


def _binding(seed: int = 1) -> ChannelBinding:
    return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, bytes((seed,)) * 32)


def test_report_data_v2_is_deterministic_and_every_field_is_unambiguous():
    nonce = b"n" * 32
    binding = _binding()
    baseline = report_data_v2(nonce, "hotkey", binding)

    assert len(baseline) == 64
    assert report_data_v2(nonce, "hotkey", binding) == baseline
    assert report_data_v2(b"m" * 32, "hotkey", binding) != baseline
    assert report_data_v2(nonce, "hotkey-2", binding) != baseline
    assert report_data_v2(nonce, "hotkey", _binding(2)) != baseline
    application = ChannelBinding(ChannelBindingType.APPLICATION_KEY_SHA256, binding.digest)
    assert report_data_v2(nonce, "hotkey", application) != baseline
    # Length framing prevents concatenation ambiguity across adjacent fields.
    assert report_data_v2(nonce, "ab", binding) != report_data_v2(nonce, "a", binding)


@pytest.mark.parametrize(
    ("nonce", "hotkey", "binding"),
    [
        (b"short", "hotkey", _binding()),
        (b"n" * 32, "", _binding()),
        (b"n" * 32, "x" * 513, _binding()),
        (b"n" * 32, "hotkey", object()),
    ],
)
def test_report_data_v2_rejects_invalid_boundaries(nonce, hotkey, binding):
    with pytest.raises(ValueError):
        report_data_v2(nonce, hotkey, binding)


def test_evidence_rejects_unknown_or_incomplete_report_data_versions():
    common = dict(
        kind=EvidenceKind.TDX,
        quote=b"quote",
        nonce=b"n" * 32,
        miner_hotkey="hotkey",
    )
    with pytest.raises(ValueError, match="unsupported"):
        Evidence(**common, report_data_version=3)
    with pytest.raises(ValueError, match="requires"):
        Evidence(**common, report_data_version=2)
    with pytest.raises(ValueError, match="legacy"):
        Evidence(**common, channel_binding=_binding())


def test_application_key_binding_is_typed_and_key_sensitive():
    first = application_key_binding(b"application-public-key-1")
    second = application_key_binding(b"application-public-key-2")

    assert first.binding_type is ChannelBindingType.APPLICATION_KEY_SHA256
    assert first != second
    with pytest.raises(ChannelBindingError):
        application_key_binding(b"")


def test_public_launch_docs_require_protected_production_channel():
    launch = Path("docs/TDX_LAUNCH.md").read_text(encoding="utf-8")
    normalized = " ".join(launch.split())
    assert "Production endpoints use HTTPS" in normalized
    assert "before writing any request bytes" in normalized
    assert "Plain HTTP is limited to the explicit development loopback" in normalized
    assert "A public certificate by itself does not prove" in normalized


def test_remote_rejects_insecure_custom_tls_context():
    context = ssl._create_unverified_context()
    with pytest.raises(ValueError, match="verify certificates"):
        RemoteMiner("https://127.0.0.1:443", HOTKEY, ssl_context=context)


@pytest.mark.parametrize(
    "malformed",
    [b"", b"\x30\x80", b"\x30\x81\x01\x00", b"\x30\x03\x30\x01"],
)
def test_spki_parser_rejects_truncated_and_noncanonical_der(malformed):
    with pytest.raises(ChannelBindingError):
        extract_spki_der(malformed)


def _certificate_pair(directory: Path, name: str) -> tuple[Path, Path, bytes]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is required for the local TLS integration test")
    key = directory / f"{name}.key.pem"
    cert = directory / f"{name}.cert.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    certificate_der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    return cert, key, certificate_der


def _bound_evidence(
    nonce: bytes,
    hotkey: str,
    *,
    channel_binding: ChannelBinding,
    report_data_version: int,
) -> Evidence:
    assert report_data_version == 2
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=report_data_v2(nonce, hotkey, channel_binding),
        nonce=nonce,
        miner_hotkey=hotkey,
        report_data_version=2,
        channel_binding=channel_binding,
    )


def _bound_composite_evidence(
    nonce: bytes,
    hotkey: str,
    *,
    channel_binding: ChannelBinding,
    report_data_version: int,
) -> tuple[Evidence, Evidence]:
    tdx = _bound_evidence(
        nonce,
        hotkey,
        channel_binding=channel_binding,
        report_data_version=report_data_version,
    )
    gpu = Evidence(
        kind=EvidenceKind.GPU_CC,
        quote=b"bounded-gpu-quote",
        cert_chain=[b"bounded-gpu-cert"],
        nonce=nonce,
        miner_hotkey=hotkey,
        composite_jwt="vendor-composite-token",
        report_data_version=2,
        channel_binding=channel_binding,
    )
    return tdx, gpu


def _sat_item() -> SatWorkItem:
    instance = SatInstance(2, [[1, 2], [-1, 2]])
    seed = 7
    return SatWorkItem(
        instance,
        seed,
        _compute_challenge_id(instance, seed),
    )


def test_tls_spki_binding_round_trip_before_protected_work(tmp_path: Path):
    cert, key, certificate_der = _certificate_pair(tmp_path, "worker")
    binding = tls_spki_binding(certificate_der)
    openssl = shutil.which("openssl")
    assert openssl is not None
    public_key_pem = subprocess.run(
        [openssl, "x509", "-in", str(cert), "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    public_key_der = subprocess.run(
        [openssl, "pkey", "-pubin", "-outform", "DER"],
        input=public_key_pem,
        check=True,
        capture_output=True,
    ).stdout
    assert extract_spki_der(certificate_der) == public_key_der
    with pytest.raises(ChannelBindingError):
        extract_spki_der(certificate_der + b"\x00")

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_evidence,
        channel_binding=binding,
        tls_context=server_context,
        allow_noncanonical_sat=True,
        bearer_token="protected-token",
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            bearer_token="protected-token",
            ssl_context=client_context,
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        assert evidence.channel_binding == binding
        assert remote.confirm_channel_binding(evidence) == binding
        certificate = remote.do_sat_work(_sat_item())

    assert certificate.assigned_hotkey == HOTKEY


def test_native_tls_server_permits_non_loopback_bind(monkeypatch):
    class FakeHttpServer:
        def __init__(self, address, _handler):
            self.server_address = address
            self.socket = object()

        def shutdown(self):
            return None

        def server_close(self):
            return None

    class FakeTlsContext(ssl.SSLContext):
        def __new__(cls):
            return super().__new__(cls, ssl.PROTOCOL_TLS_SERVER)

        def wrap_socket(self, socket, *, server_side):
            assert server_side is True
            return ("tls", socket)

    monkeypatch.setattr("cathedral.worker.ThreadingHTTPServer", FakeHttpServer)

    with WorkerServer(
        "0.0.0.0",
        configured_hotkey=HOTKEY,
        channel_binding=_binding(),
        tls_context=FakeTlsContext(),
    ) as server:
        assert server.host == "0.0.0.0"
        assert server.base_url.startswith("https://")


def test_tls_worker_remote_round_trip_carries_exact_composite_bundle(tmp_path: Path):
    cert, key, certificate_der = _certificate_pair(tmp_path, "gpu-worker")
    binding = tls_spki_binding(certificate_der)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_composite_evidence,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            max_response_body=MAX_EVIDENCE_RESPONSE_BODY,
            ssl_context=client_context,
        )
        evidences = remote.fetch_evidence_bundle(os.urandom(32))
        tdx = next(item for item in evidences if item.kind is EvidenceKind.TDX)
        gpu = next(item for item in evidences if item.kind is EvidenceKind.GPU_CC)

        assert len(evidences) == 2
        assert tdx.channel_binding == gpu.channel_binding == binding
        assert gpu.composite_jwt == "vendor-composite-token"
        assert remote.confirm_channel_binding(tdx) == binding


def test_composite_wire_contract_carries_evidence_above_legacy_body_caps(
    tmp_path: Path,
):
    cert, key, certificate_der = _certificate_pair(tmp_path, "gpu-large-wire")
    binding = tls_spki_binding(certificate_der)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))

    def large_composite(*args, **kwargs):
        tdx, gpu = _bound_composite_evidence(*args, **kwargs)
        return tdx, replace(gpu, quote=b"g" * (192 * 1024))

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=large_composite,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            max_response_body=MAX_EVIDENCE_RESPONSE_BODY,
            ssl_context=client_context,
        )
        evidences = remote.fetch_evidence_bundle(os.urandom(32))

    gpu = next(item for item in evidences if item.kind is EvidenceKind.GPU_CC)
    assert gpu.quote == b"g" * (192 * 1024)


def test_worker_remote_runtime_accepts_bound_composite_in_audit_mode(tmp_path: Path, monkeypatch):
    cert, key, certificate_der = _certificate_pair(tmp_path, "gpu-runtime")
    binding = tls_spki_binding(certificate_der)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    gpu_uuid = "GPU-11111111-1111-4111-8111-111111111111"
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = GpuProfile(
        profile_id="tdx-h100-audit-v1",
        expected_device_identity_digests=frozenset({gpu_identity_policy_digest(gpu_uuid)}),
        allowed_models=frozenset({"NVIDIA-H100-80GB-HBM3"}),
        allowed_cc_modes=frozenset({"CC-On"}),
        allowed_drivers=frozenset({"550.90.07"}),
        allowed_vbios=frozenset({"96.00.5E.00.01"}),
        allowed_security_states=frozenset({"Secure"}),
        allowed_cpu_measurements=frozenset({"cpu-measurement"}),
        verifier_digest="sha256:" + "a" * 64,
        active=True,
    )

    def cpu_verify(evidence, nonce, selected_policy):
        assert evidence.kind is EvidenceKind.TDX
        assert evidence.nonce == nonce
        return Attested(
            Tier.CC_CPU_TDX,
            "tdx-platform-sha256:" + "1" * 64,
            "cpu-measurement",
            1,
            assurance=attestation_claims(evidence.quote, selected_policy),
        )

    class AuditGpuVerifier:
        def verify(
            self,
            evidence,
            selected_profile,
            *,
            tdx_evidence,
            tdx_verdict,
        ):
            assert evidence.channel_binding is not None
            challenge = (
                "sha256:"
                + gpu_challenge(
                    evidence.nonce, evidence.miner_hotkey, evidence.channel_binding
                ).hex()
            )
            return GpuComponentVerdict(
                (
                    GpuDeviceClaim(
                        gpu_uuid,
                        "NVIDIA-H100-80GB-HBM3",
                        "CC-On",
                        "550.90.07",
                        "96.00.5E.00.01",
                        "Secure",
                        True,
                    ),
                ),
                "sha256:" + hashlib.sha256(evidence.quote).hexdigest(),
                challenge,
                gpu_host_session_digest(
                    evidence.nonce,
                    evidence.miner_hotkey,
                    evidence.channel_binding,
                ),
                selected_profile.digest,
                tdx_component_binding_digest(tdx_evidence, tdx_verdict),
                None,
            )

    monkeypatch.setattr("cathedral.verify.verify", cpu_verify)
    identity_registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    ledger = Ledger(tmp_path / "ledger.sqlite")

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_composite_evidence,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def remote_factory(endpoint, hotkey, **kwargs):
            return RemoteMiner(
                endpoint,
                hotkey,
                timeout=kwargs["timeout"],
                max_response_body=kwargs["max_response_body"],
                ssl_context=client_context,
            )

        runtime = ConfidentialRuntime(
            registry,
            ledger,
            policy,
            remote_factory=remote_factory,
            config=RuntimeConfig(
                miner_attempts=1,
                production_mode=False,
                expected_tier=Tier.CC_GPU,
            ),
            gpu_profile=profile,
            gpu_verifier=AuditGpuVerifier(),
            gpu_identity_registry=identity_registry,
        )
        outcome = runtime.audit_attestation(MinerTarget(HOTKEY, server.base_url))
        runtime.close()

    assert outcome.status == "attestation_verified"
    assert outcome.admitted is False
    assert outcome.assurance is not None
    assert outcome.assurance.channel.status is ClaimStatus.PASSED
    assert outcome.component_audit is not None
    assert outcome.component_audit["schema"] == "cathedral_composite_gpu_audit_v1"
    assert outcome.component_audit["gpu"]["device_count"] == 1
    assert gpu_uuid not in str(outcome.component_audit)
    with sqlite3.connect(identity_registry.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM gpu_identity_claims_v3").fetchone()[0] == 0


def test_scored_gpu_epoch_rejects_same_gpu_on_different_tdx_host(tmp_path: Path, monkeypatch):
    cert, key, certificate_der = _certificate_pair(tmp_path, "shared-gpu-hosts")
    binding = tls_spki_binding(certificate_der)
    server_context_one = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context_one.load_cert_chain(cert, key)
    server_context_two = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context_two.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    gpu_uuid = "GPU-11111111-1111-4111-8111-111111111111"
    policy = Policy(allowed_measurements=frozenset({"cpu-measurement"}))
    profile = GpuProfile(
        profile_id="tdx-h100-score-v1",
        expected_device_identity_digests=frozenset({gpu_identity_policy_digest(gpu_uuid)}),
        allowed_models=frozenset({"NVIDIA-H100-80GB-HBM3"}),
        allowed_cc_modes=frozenset({"CC-On"}),
        allowed_drivers=frozenset({"550.90.07"}),
        allowed_vbios=frozenset({"96.00.5E.00.01"}),
        allowed_security_states=frozenset({"Secure"}),
        allowed_cpu_measurements=frozenset({"cpu-measurement"}),
        verifier_digest="sha256:" + "a" * 64,
        active=True,
    )

    def cpu_verify(evidence, nonce, selected_policy):
        assert evidence.nonce == nonce
        return Attested(
            Tier.CC_CPU_TDX,
            "tdx-platform-sha256:" + hashlib.sha256(evidence.miner_hotkey.encode()).hexdigest(),
            "cpu-measurement",
            1,
            assurance=attestation_claims(evidence.quote, selected_policy),
        )

    class SharedGpuVerifier:
        def verify(
            self,
            evidence,
            selected_profile,
            *,
            tdx_evidence,
            tdx_verdict,
        ):
            assert evidence.channel_binding is not None
            return GpuComponentVerdict(
                (
                    GpuDeviceClaim(
                        gpu_uuid,
                        "NVIDIA-H100-80GB-HBM3",
                        "CC-On",
                        "550.90.07",
                        "96.00.5E.00.01",
                        "Secure",
                        True,
                    ),
                ),
                "sha256:" + hashlib.sha256(evidence.quote).hexdigest(),
                "sha256:"
                + gpu_challenge(
                    evidence.nonce,
                    evidence.miner_hotkey,
                    evidence.channel_binding,
                ).hex(),
                gpu_host_session_digest(
                    evidence.nonce,
                    evidence.miner_hotkey,
                    evidence.channel_binding,
                ),
                selected_profile.digest,
                tdx_component_binding_digest(tdx_evidence, tdx_verdict),
                None,
            )

    monkeypatch.setattr("cathedral.verify.verify", cpu_verify)
    monkeypatch.setenv("CATHEDRAL_ENABLE_GPU_SCORING", "true")
    monkeypatch.setenv(
        "CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES",
        gpu_profile_authority(profile),
    )
    identity_registry = GpuIdentityRegistry(
        tmp_path / "scored-gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )
    registry = RegistryStore(str(tmp_path / "scored-registry.sqlite"))
    ledger = Ledger(tmp_path / "scored-ledger.sqlite")

    with (
        WorkerServer(
            configured_hotkey="gpu-canary",
            evidence_collector=_bound_composite_evidence,
            channel_binding=binding,
            tls_context=server_context_one,
        ) as canary_server,
        WorkerServer(
            configured_hotkey="gpu-miner",
            evidence_collector=_bound_composite_evidence,
            channel_binding=binding,
            tls_context=server_context_two,
        ) as miner_server,
    ):
        threading.Thread(target=canary_server.serve_forever, daemon=True).start()
        threading.Thread(target=miner_server.serve_forever, daemon=True).start()
        registry.enroll("gpu-miner", miner_server.base_url)

        def remote_factory(endpoint, hotkey, **kwargs):
            return RemoteMiner(
                endpoint,
                hotkey,
                timeout=kwargs["timeout"],
                max_response_body=kwargs["max_response_body"],
                ssl_context=client_context,
            )

        runtime = ConfidentialRuntime(
            registry,
            ledger,
            policy,
            remote_factory=remote_factory,
            config=RuntimeConfig(
                miner_attempts=1,
                production_mode=False,
                expected_tier=Tier.CC_GPU,
            ),
            gpu_profile=profile,
            gpu_verifier=SharedGpuVerifier(),
            gpu_identity_registry=identity_registry,
        )
        with pytest.raises(CathedralRuntimeError, match="shares the dedicated canary GPU identity"):
            runtime.run_epoch(1, MinerTarget("gpu-canary", canary_server.base_url))
        runtime.close()

    assert ledger.get_epoch(1) is None
    with sqlite3.connect(identity_registry.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM gpu_identity_claims_v3").fetchone()[0] == 0
    ledger.close()


def test_gpu_runtime_rejects_receipt_issuance_before_composite_schema(tmp_path: Path):
    gpu_uuid = "GPU-11111111-1111-4111-8111-111111111111"
    profile = GpuProfile(
        profile_id="tdx-h100-audit-v1",
        expected_device_identity_digests=frozenset({gpu_identity_policy_digest(gpu_uuid)}),
        allowed_models=frozenset({"NVIDIA-H100-80GB-HBM3"}),
        allowed_cc_modes=frozenset({"CC-On"}),
        allowed_drivers=frozenset({"550.90.07"}),
        allowed_vbios=frozenset({"96.00.5E.00.01"}),
        allowed_security_states=frozenset({"Secure"}),
        allowed_cpu_measurements=frozenset({"cpu-measurement"}),
        verifier_digest="sha256:" + "a" * 64,
        active=True,
    )
    ledger = Ledger(tmp_path / "ledger.sqlite")
    with pytest.raises(ValueError, match="composite receipt schema"):
        ConfidentialRuntime(
            RegistryStore(str(tmp_path / "registry.sqlite")),
            ledger,
            Policy(),
            config=RuntimeConfig(production_mode=False, expected_tier=Tier.CC_GPU),
            receipt_issuer=object(),
            gpu_profile=profile,
            gpu_verifier=object(),
            gpu_identity_registry=GpuIdentityRegistry(
                tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
            ),
        )
    ledger.close()


def test_production_gpu_runtime_requires_signed_profile_and_external_verifier(
    tmp_path: Path,
):
    gpu_uuid = "GPU-11111111-1111-4111-8111-111111111111"
    profile = GpuProfile(
        profile_id="tdx-h100-audit-v1",
        expected_device_identity_digests=frozenset({gpu_identity_policy_digest(gpu_uuid)}),
        allowed_models=frozenset({"NVIDIA-H100-80GB-HBM3"}),
        allowed_cc_modes=frozenset({"CC-On"}),
        allowed_drivers=frozenset({"550.90.07"}),
        allowed_vbios=frozenset({"96.00.5E.00.01"}),
        allowed_security_states=frozenset({"Secure"}),
        allowed_cpu_measurements=frozenset({"cpu-measurement"}),
        verifier_digest="sha256:" + "a" * 64,
        active=True,
    )
    identity_database_parent = tmp_path / "identity-database"
    identity_anchor_parent = tmp_path / "identity-anchor"
    identity_database_parent.mkdir(mode=0o700)
    identity_anchor_parent.mkdir(mode=0o700)
    identity_registry = GpuIdentityRegistry(
        identity_database_parent / "gpu-identities.sqlite",
        identity_digest_key=b"i" * 32,
        production_mode=True,
        generation_anchor_path=identity_anchor_parent / "generation.anchor",
        initialize=True,
    )
    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    ledger = Ledger(tmp_path / "ledger.sqlite")
    config = RuntimeConfig(production_mode=True, expected_tier=Tier.CC_GPU)

    with pytest.raises(ValueError, match="live profile"):
        ConfidentialRuntime(
            registry,
            ledger,
            Policy(),
            config=config,
            gpu_profile=profile,
            gpu_verifier=object(),
            gpu_identity_registry=identity_registry,
        )

    signed_profile = replace(
        profile,
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
    )
    now = datetime.now(UTC)
    object.__setattr__(signed_profile, "registry_valid_from", now - timedelta(days=1))
    object.__setattr__(signed_profile, "registry_valid_until", now + timedelta(days=1))
    object.__setattr__(signed_profile, "_registry_verified", True)
    signed_policy = Policy(
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
    )
    with pytest.raises(ValueError, match="pinned external verifier"):
        ConfidentialRuntime(
            registry,
            ledger,
            signed_policy,
            config=config,
            gpu_profile=signed_profile,
            gpu_verifier=object(),
            gpu_identity_registry=identity_registry,
        )

    native_executable = str(Path(shutil.which("true") or "/usr/bin/true").resolve())
    development_verifier = ExternalGpuVerifier(
        ExternalVerifierConfig(
            (native_executable,),
            implementation_artifacts=(native_executable,),
        ),
        production_mode=False,
    )
    signed_development_profile = replace(
        signed_profile,
        verifier_digest=development_verifier.implementation_digest,
    )
    object.__setattr__(
        signed_development_profile, "registry_valid_from", now - timedelta(days=1)
    )
    object.__setattr__(
        signed_development_profile, "registry_valid_until", now + timedelta(days=1)
    )
    object.__setattr__(signed_development_profile, "_registry_verified", True)
    with pytest.raises(ValueError, match="static verifier executable"):
        ConfidentialRuntime(
            registry,
            ledger,
            signed_policy,
            config=config,
            gpu_profile=signed_development_profile,
            gpu_verifier=development_verifier,
            gpu_identity_registry=identity_registry,
        )
    ledger.close()


def test_gpu_identity_registry_corruption_aborts_without_worker_revocation(
    tmp_path: Path, monkeypatch
):
    gpu_uuid = "GPU-11111111-1111-4111-8111-111111111111"
    profile = GpuProfile(
        profile_id="tdx-h100-audit-v1",
        expected_device_identity_digests=frozenset({gpu_identity_policy_digest(gpu_uuid)}),
        allowed_models=frozenset({"NVIDIA-H100-80GB-HBM3"}),
        allowed_cc_modes=frozenset({"CC-On"}),
        allowed_drivers=frozenset({"550.90.07"}),
        allowed_vbios=frozenset({"96.00.5E.00.01"}),
        allowed_security_states=frozenset({"Secure"}),
        allowed_cpu_measurements=frozenset({"cpu-measurement"}),
        verifier_digest="sha256:" + "a" * 64,
        active=True,
    )
    component = GpuComponentVerdict(
        devices=(
            GpuDeviceClaim(
                gpu_uuid,
                "NVIDIA-H100-80GB-HBM3",
                "CC-On",
                "550.90.07",
                "96.00.5E.00.01",
                "Secure",
                True,
            ),
        ),
        evidence_digest="sha256:" + "1" * 64,
        challenge_digest="sha256:" + "2" * 64,
        host_session_digest="sha256:" + "3" * 64,
        profile_digest="sha256:" + "4" * 64,
        tdx_component_digest="sha256:" + "5" * 64,
        topology_digest=None,
    )
    identity_registry = GpuIdentityRegistry(
        tmp_path / "gpu-identities.sqlite", identity_digest_key=b"i" * 32
    )

    def corrupt_registry(*_args, **_kwargs):
        raise GpuAttestationError(
            "identity_config_invalid", "GPU identity registry authentication failed"
        )

    monkeypatch.setattr(identity_registry, "begin_claim", corrupt_registry)
    registry = RegistryStore(str(tmp_path / "registry.sqlite"))
    registry.enroll("gpu-worker", "http://127.0.0.1:9001")
    snapshot = registry.lifecycle_snapshot("gpu-worker", materialize_freshness=False)
    ledger = Ledger(tmp_path / "ledger.sqlite")
    runtime = ConfidentialRuntime(
        registry,
        ledger,
        Policy(),
        config=RuntimeConfig(production_mode=False, expected_tier=Tier.CC_GPU),
        gpu_profile=profile,
        gpu_verifier=object(),
        gpu_identity_registry=identity_registry,
    )
    result = _AttestationResult(
        MinerTarget("gpu-worker", "http://127.0.0.1:9001"),
        "http://127.0.0.1:9001",
        attested=Attested(
            Tier.CC_GPU,
            "tdx-chip",
            "composite-measurement",
            1,
            "VERIFIED",
        ),
        evidence_digest="sha256:" + "6" * 64,
        gpu_component=component,
        lifecycle_generation=snapshot.generation,
        lifecycle_revision=snapshot.revision,
    )

    with pytest.raises(GpuAttestationError) as raised:
        runtime._admit_unique_chips(1, [result], {})

    assert raised.value.category == "identity_config_invalid"
    assert (
        registry.lifecycle_snapshot("gpu-worker", materialize_freshness=False).state.value
        == "pending"
    )
    runtime.close()
    ledger.close()


def test_tls_worker_rejects_live_key_not_owned_by_attested_configuration(
    tmp_path: Path,
):
    cert, key, _ = _certificate_pair(tmp_path, "worker")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_evidence,
        channel_binding=_binding(),
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(server.base_url, HOTKEY, ssl_context=client_context)
        with pytest.raises(RemoteError, match="HTTP 403"):
            remote.fetch_evidence(os.urandom(32))


def test_certificate_rotation_between_attestation_and_work_fails_before_dispatch(
    tmp_path: Path,
):
    cert_a, key_a, der_a = _certificate_pair(tmp_path, "worker-a")
    cert_b, key_b, _ = _certificate_pair(tmp_path, "worker-b")
    binding_a = tls_spki_binding(der_a)

    context_a = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_a.load_cert_chain(cert_a, key_a)
    context_b = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_b.load_cert_chain(cert_b, key_b)
    handshakes = 0

    def rotate(ssl_socket, _server_name, _initial_context):
        nonlocal handshakes
        handshakes += 1
        ssl_socket.context = context_a if handshakes == 1 else context_b

    context_a.set_servername_callback(rotate)
    client_context = ssl.create_default_context()
    client_context.load_verify_locations(cafile=str(cert_a))
    client_context.load_verify_locations(cafile=str(cert_b))

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_evidence,
        channel_binding=binding_a,
        tls_context=context_a,
        allow_noncanonical_sat=True,
        bearer_token="must-not-be-sent-on-changed-key",
    ) as server:
        server._server.handle_error = lambda _request, _address: None
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            bearer_token="must-not-be-sent-on-changed-key",
            ssl_context=client_context,
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)
        with pytest.raises(RemoteError, match="channel key changed"):
            remote.do_sat_work(_sat_item())

    assert handshakes == 2


def test_failed_fresh_evidence_attempt_clears_previously_trusted_binding(
    tmp_path: Path,
):
    cert, key, certificate_der = _certificate_pair(tmp_path, "worker")
    binding = tls_spki_binding(certificate_der)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))

    calls = 0

    def fail_second_collection(
        nonce: bytes,
        hotkey: str,
        *,
        channel_binding: ChannelBinding,
        report_data_version: int,
    ) -> Evidence:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated fresh-evidence failure")
        return _bound_evidence(
            nonce,
            hotkey,
            channel_binding=channel_binding,
            report_data_version=report_data_version,
        )

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=fail_second_collection,
        channel_binding=binding,
        tls_context=server_context,
        allow_noncanonical_sat=True,
        bearer_token="protected-token",
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            bearer_token="protected-token",
            ssl_context=client_context,
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)
        with pytest.raises(RemoteError, match="HTTP 500"):
            remote.fetch_evidence(os.urandom(32))
        with pytest.raises(RemoteError, match="required before work"):
            remote.do_sat_work(_sat_item())
