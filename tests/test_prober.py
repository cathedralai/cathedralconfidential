"""Prober tests: TDX-CPU launch path, fault isolation, production gates.

No SNP fixtures or cathedral.verify.snp dependency. All attestation evidence
is TDX, verified via a monkeypatched verifier returning Attested(CC_CPU_TDX).
GPU composite path remains fail-closed (no GPU verifier wired in).
"""

from __future__ import annotations

import base64
import argparse
import json
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import cathedral.prober as prober_module
import pytest
from cathedral.assurance import attestation_claims
from cathedral.common import (
    Attested,
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    Policy,
    Tier,
)
from cathedral.enroll import RegistryStore
from cathedral.lifecycle import WorkerLifecycleState
from cathedral.prober import policy_from_args, probe_once


def test_policy_from_args_supports_strict_tdx_flags():
    args = argparse.Namespace(
        allow_measurement=["m"],
        allow_measurements_file=None,
        min_tcb=0,
        tdx_strict=True,
        allow_tdx_tcb_status=["UpToDate", "SWHardeningNeeded"],
        allow_tdx_advisory=["INTEL-SA-01234"],
    )

    policy = policy_from_args(args)

    assert policy.tdx_strict is True
    assert policy.tdx_allowed_tcb_statuses == {"UpToDate", "SWHardeningNeeded"}
    assert policy.tdx_allowed_advisories == {"INTEL-SA-01234"}


def test_policy_from_legacy_args_defaults_to_visible_compatibility_mode():
    args = argparse.Namespace(allow_measurement=["m"], allow_measurements_file=None, min_tcb=0)

    policy = policy_from_args(args)

    assert policy.tdx_strict is False
    assert policy.tdx_allowed_tcb_statuses == {"UpToDate"}


def test_prober_cli_wires_signed_gpu_configuration(monkeypatch, tmp_path):
    policy = Policy(
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
    )
    snapshot = object()
    profile = object()
    gpu_verifier = object()
    identity_registry = object()
    captured = []

    monkeypatch.setattr(
        "cathedral.cli._verified_registry_snapshot_and_policy",
        lambda *_args, **_kwargs: (policy, snapshot),
    )
    monkeypatch.setattr(
        "cathedral.cli._load_gpu_identity_key",
        lambda *_args, **_kwargs: b"i" * 32,
    )
    monkeypatch.setattr(
        "cathedral.gpu.gpu_profile_from_registry",
        lambda received, profile_id: (
            profile if (received, profile_id) == (snapshot, "gpu-profile") else None
        ),
    )
    monkeypatch.setattr(
        "cathedral.gpu.gpu_verifier_from_env",
        lambda **_kwargs: gpu_verifier,
    )
    monkeypatch.setattr(
        "cathedral.gpu.GpuIdentityRegistry",
        lambda *_args, **_kwargs: identity_registry,
    )
    monkeypatch.setattr(
        prober_module,
        "probe_once",
        lambda store, received_policy, **kwargs: (
            captured.append((store, received_policy, kwargs)) or True
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cathedral-prober",
            "--db",
            str(tmp_path / "registry.sqlite"),
            "--once",
            "--policy-registry",
            "registry.json",
            "--policy-registry-keys",
            "keys.json",
            "--policy-registry-state",
            str(tmp_path / "policy-state.sqlite"),
            "--gpu-profile-id",
            "gpu-profile",
            "--gpu-identity-db",
            str(tmp_path / "gpu-identities.sqlite"),
            "--gpu-identity-key-file",
            "gpu-identity.key",
            "--gpu-identity-anchor-file",
            str(tmp_path / "gpu-generation.anchor"),
        ],
    )

    prober_module.main()

    assert len(captured) == 1
    _store, received_policy, kwargs = captured[0]
    assert received_policy is policy
    assert kwargs["gpu_profile"] is profile
    assert kwargs["gpu_verifier"] is gpu_verifier
    assert kwargs["gpu_identity_registry"] is identity_registry
    assert kwargs["expected_tier"] is Tier.CC_GPU


# ---------------------------------------------------------------------------
# Shared TDX evidence fixtures
# ---------------------------------------------------------------------------

TDX_QUOTE = b"\x04\x00" + b"\xaa" * 254  # 256-byte synthetic TDX quote
TDX_CHIP_ID = "tdx-platform-" + "ab" * 16
TDX_MEASUREMENT = "tdx-measurement-" + "cd" * 16


def _evidence_item(kind: str, quote: bytes, payload: dict) -> dict:
    return {
        "kind": kind,
        "quote_b64": base64.b64encode(quote).decode("ascii"),
        "nonce_hex": payload["nonce_hex"],
        "miner_hotkey": payload["hotkey"],
        "cert_chain_b64": [],
    }


# ---------------------------------------------------------------------------
# HTTP miner stubs
# ---------------------------------------------------------------------------


class TdxMiner(BaseHTTPRequestHandler):
    """Serves a single TDX evidence item."""

    hotkey = "5" + "T" * 47
    hits = 0

    def do_POST(self):  # noqa: N802
        type(self).hits += 1
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        body = json.dumps(_evidence_item("tdx", TDX_QUOTE, payload)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class TdxMiner2(TdxMiner):
    """Second TDX miner with a distinct hotkey."""

    hotkey = "5" + "U" * 47


def _serve(handler_cls):
    handler_cls.hits = 0
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _fake_tdx_verify(evidence, nonce, policy):
    """Monkeypatched verifier: returns Attested(CC_CPU_TDX) for TDX evidence."""
    if evidence.kind is EvidenceKind.TDX:
        return Attested(
            tier=Tier.CC_CPU_TDX,
            chip_id=TDX_CHIP_ID,
            measurement=TDX_MEASUREMENT,
            tcb=3,
            assurance=attestation_claims(evidence.quote, policy),
        )
    return None


def _production_policy() -> Policy:
    policy = Policy(
        allowed_measurements={TDX_MEASUREMENT},
        tdx_strict=True,
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
        registry_profile_ids=("cpu-tdx-v1",),
    )
    object.__setattr__(policy, "_registry_verified", True)
    object.__setattr__(policy, "_registry_valid_from", datetime.now(UTC) - timedelta(days=1))
    object.__setattr__(policy, "_registry_valid_until", datetime.now(UTC) + timedelta(days=1))
    return policy


# ---------------------------------------------------------------------------
# Test: verified TDX evidence -> VERIFIED verdict
# ---------------------------------------------------------------------------


def test_prober_verified_tdx_evidence(monkeypatch, tmp_path):
    """A miner serving valid TDX evidence receives a VERIFIED verdict via the
    TDX-CPU launch path."""
    server = _serve(TdxMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = TdxMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")

    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)
    probe_once(store, Policy())
    server.shutdown()

    board = store.board()
    assert board["count"] == 1
    assert board["miners"][0]["verification_status"] == "VERIFIED"
    assert board["miners"][0]["tier"] == Tier.CC_CPU_TDX.value
    assert board["miners"][0]["chip_id_prefix"] == TDX_CHIP_ID[:16]


def test_prober_transient_failure_recovers_without_manual_reenrollment(monkeypatch, tmp_path):
    server = _serve(TdxMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = TdxMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")
    original_request = prober_module._request_evidence
    calls = 0

    def flaky_request(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("temporary timeout")
        return original_request(*args, **kwargs)

    monkeypatch.setattr(prober_module, "_request_evidence", flaky_request)
    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)

    probe_once(store, Policy())
    pending = store.lifecycle_snapshot(hotkey)
    assert pending.state is WorkerLifecycleState.PENDING
    assert pending.retry_count == 1
    assert store.board()["miners"][0]["verification_status"] == "FAILED"

    # Polling before the durable retry is due does not make another request.
    probe_once(store, Policy())
    assert calls == 1

    # Once the persisted retry becomes due, a successful probe can recover the
    # pending worker without manual reenrollment.
    pending_retry = pending.next_retry_at
    assert pending_retry is not None
    store._clock = lambda: pending_retry
    probe_once(store, Policy())
    server.shutdown()

    recovered = store.lifecycle_snapshot(hotkey)
    assert recovered.state is WorkerLifecycleState.ATTESTED
    assert recovered.retry_count == 0
    assert store.board()["miners"][0]["verification_status"] == "VERIFIED"


def test_prober_rejects_verified_flag_without_typed_assurance(monkeypatch, tmp_path):
    server = _serve(TdxMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = TdxMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")

    def legacy_verifier(evidence, nonce, policy):
        return Attested(Tier.CC_CPU_TDX, "chip", "measurement", 1, "VERIFIED")

    monkeypatch.setattr("cathedral.prober.verifier.verify", legacy_verifier)
    probe_once(store, Policy())
    server.shutdown()

    assert store.board()["miners"][0]["verification_status"] == "FAILED"


# ---------------------------------------------------------------------------
# Test: TDX verification failure -> FAILED verdict
# ---------------------------------------------------------------------------


def test_prober_failed_tdx_verification(monkeypatch, tmp_path):
    """When the verifier rejects TDX evidence (returns None), the miner is
    recorded as FAILED."""
    server = _serve(TdxMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = TdxMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")

    def reject_all(evidence, nonce, policy):
        return None

    monkeypatch.setattr("cathedral.prober.verifier.verify", reject_all)
    probe_once(store, Policy())
    server.shutdown()

    board = store.board()
    assert board["count"] == 0
    assert board["miners"][0]["verification_status"] == "FAILED"


# ---------------------------------------------------------------------------
# Test: unreachable endpoint -> FAILED (fault isolation)
# ---------------------------------------------------------------------------


def test_prober_unreachable_endpoint_records_failed(tmp_path):
    """An unreachable miner endpoint records FAILED without affecting others."""
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "D" * 47
    store.enroll(hotkey, "http://127.0.0.1:9")

    probe_once(store, Policy())

    board = store.board()
    assert board["count"] == 0
    assert board["miners"][0]["verification_status"] == "FAILED"


def test_prober_fault_isolation_unreachable_does_not_block_valid(monkeypatch, tmp_path):
    """An unreachable miner does not prevent a valid TDX miner from being
    probed and verified in the same pass."""
    server = _serve(TdxMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    bad_hotkey = "5" + "D" * 47
    store.enroll(bad_hotkey, "http://127.0.0.1:9")

    good_hotkey = TdxMiner.hotkey
    store.enroll(good_hotkey, f"http://127.0.0.1:{server.server_port}")

    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)
    probe_once(store, Policy(), max_workers=2)
    server.shutdown()

    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}
    assert statuses[bad_hotkey] == "FAILED"
    assert statuses[good_hotkey] == "VERIFIED"
    assert board["count"] == 1


# ---------------------------------------------------------------------------
# Test: production mode rejects non-global IP literals
# ---------------------------------------------------------------------------


def test_production_mode_rejects_non_global_ip_before_network(monkeypatch, tmp_path):
    """In production_mode, local IP literals are rejected before the opener
    is ever invoked."""
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    policy = _production_policy()
    monkeypatch.setattr("cathedral.prober.verifier.preflight_tdx_verifier", lambda _policy: None)

    test_cases = [
        ("5" + "A" * 47, "http://127.0.0.1:8080"),
        ("5" + "B" * 47, "http://192.168.1.100:8080"),
        ("5" + "C" * 47, "http://10.0.0.1:8080"),
        ("5" + "D" * 47, "http://172.16.0.1:8080"),
        ("5" + "E" * 47, "http://169.254.1.1:8080"),
        ("5" + "F" * 47, "http://[::1]:8080"),
        ("5" + "G" * 47, "http://[fe80::1]:8080"),
        ("5" + "H" * 47, "http://[fc00::1]:8080"),
    ]

    for hotkey, endpoint_url in test_cases:
        store.enroll(hotkey, endpoint_url)

    opener_called = []

    def mock_opener(*args, **kwargs):
        opener_called.append(True)
        raise RuntimeError("opener should never be called")

    probe_once(
        store,
        policy,
        opener=mock_opener,
        production_mode=True,
        policy_refresher=lambda: policy,
    )

    assert not opener_called, "opener was invoked for a local IP literal in production mode"

    board = store.board()
    assert board["count"] == 0
    for miner in board["miners"]:
        assert miner["verification_status"] == "FAILED"


def test_production_probe_rejects_unsigned_policy_before_network(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "J" * 47
    store.enroll(hotkey, "https://8.8.8.8:443")
    with pytest.raises(ValueError, match="strict signed CPU policy"):
        probe_once(store, Policy(), production_mode=True)
    assert store.board()["miners"][0]["verification_status"] == "PENDING"


def test_production_probe_requires_live_policy_refresher(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    with pytest.raises(ValueError, match="live policy registry refresher"):
        probe_once(store, _production_policy(), production_mode=True)


def test_production_probe_persists_verified_channel_claim(monkeypatch, tmp_path):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32)

    class BoundRemote:
        def __init__(self, endpoint, hotkey, *, timeout):
            assert endpoint == "https://8.8.8.8:443"
            assert timeout == 5
            self.hotkey = hotkey

        def fetch_evidence(self, nonce):
            return Evidence(
                EvidenceKind.TDX,
                TDX_QUOTE,
                nonce,
                self.hotkey,
                report_data_version=2,
                channel_binding=binding,
            )

        def confirm_channel_binding(self, evidence):
            assert evidence.channel_binding == binding
            return binding

    monkeypatch.setattr("cathedral.prober.RemoteMiner", BoundRemote)
    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)
    monkeypatch.setattr("cathedral.prober.verifier.preflight_tdx_verifier", lambda _policy: None)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "P" * 47
    store.enroll(hotkey, "https://8.8.8.8:443")

    policy = _production_policy()
    probe_once(
        store,
        policy,
        production_mode=True,
        policy_refresher=lambda: policy,
    )

    miner = store.board()["miners"][0]
    assert miner["verification_status"] == "VERIFIED"
    assert miner["assurance"]["claims"]["channel"]["status"] == "passed"


def test_production_probe_rejects_policy_expiry_before_verdict_commit(monkeypatch, tmp_path):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32)
    policy = _production_policy()

    class BoundRemote:
        def __init__(self, endpoint, hotkey, *, timeout):
            self.hotkey = hotkey

        def fetch_evidence(self, nonce):
            return Evidence(
                EvidenceKind.TDX,
                TDX_QUOTE,
                nonce,
                self.hotkey,
                report_data_version=2,
                channel_binding=binding,
            )

        def confirm_channel_binding(self, evidence):
            return binding

    def expiring_verify(evidence, nonce, active_policy):
        attested = _fake_tdx_verify(evidence, nonce, active_policy)
        object.__setattr__(
            policy, "_registry_valid_until", datetime.now(UTC) - timedelta(seconds=1)
        )
        return attested

    monkeypatch.setattr("cathedral.prober.RemoteMiner", BoundRemote)
    monkeypatch.setattr("cathedral.prober.verifier.verify", expiring_verify)
    monkeypatch.setattr("cathedral.prober.verifier.preflight_tdx_verifier", lambda _policy: None)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    store.enroll("5" + "R" * 47, "https://8.8.8.8:443")

    assert (
        probe_once(
            store,
            policy,
            production_mode=True,
            policy_refresher=lambda: policy,
        )
        is False
    )
    assert store.board()["miners"][0]["verification_status"] != "VERIFIED"


def test_production_probe_rejects_superseding_release_before_verdict_commit(monkeypatch, tmp_path):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32)
    initial = _production_policy()
    replacement = _production_policy()
    object.__setattr__(replacement, "registry_release", 8)
    object.__setattr__(replacement, "registry_digest", "sha256:" + "8" * 64)
    object.__setattr__(replacement, "allowed_measurements", frozenset({"revoked-replacement"}))
    current = [initial]

    class BoundRemote:
        def __init__(self, endpoint, hotkey, *, timeout):
            self.hotkey = hotkey

        def fetch_evidence(self, nonce):
            return Evidence(
                EvidenceKind.TDX,
                TDX_QUOTE,
                nonce,
                self.hotkey,
                report_data_version=2,
                channel_binding=binding,
            )

        def confirm_channel_binding(self, evidence):
            return binding

    def superseding_verify(evidence, nonce, active_policy):
        attested = _fake_tdx_verify(evidence, nonce, active_policy)
        current[0] = replacement
        return attested

    monkeypatch.setattr("cathedral.prober.RemoteMiner", BoundRemote)
    monkeypatch.setattr("cathedral.prober.verifier.verify", superseding_verify)
    monkeypatch.setattr("cathedral.prober.verifier.preflight_tdx_verifier", lambda _policy: None)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    store.enroll("5" + "S" * 47, "https://8.8.8.8:443")

    assert (
        probe_once(
            store,
            initial,
            production_mode=True,
            policy_refresher=lambda: current[0],
        )
        is False
    )
    assert store.board()["miners"][0]["verification_status"] != "VERIFIED"


def test_production_probe_channel_mismatch_records_failed(monkeypatch, tmp_path):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32)

    class MismatchedRemote:
        def __init__(self, endpoint, hotkey, *, timeout):
            self.hotkey = hotkey

        def fetch_evidence(self, nonce):
            return Evidence(
                EvidenceKind.TDX,
                TDX_QUOTE,
                nonce,
                self.hotkey,
                report_data_version=2,
                channel_binding=binding,
            )

        def confirm_channel_binding(self, evidence):
            return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"b" * 32)

    monkeypatch.setattr("cathedral.prober.RemoteMiner", MismatchedRemote)
    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)
    monkeypatch.setattr("cathedral.prober.verifier.preflight_tdx_verifier", lambda _policy: None)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "Q" * 47
    store.enroll(hotkey, "https://8.8.4.4:443")

    policy = _production_policy()
    probe_once(
        store,
        policy,
        production_mode=True,
        policy_refresher=lambda: policy,
    )

    assert store.board()["miners"][0]["verification_status"] == "FAILED"


def test_prober_console_once_exits_nonzero_when_due_target_fails(tmp_path):
    database = tmp_path / "registry.sqlite"
    store = RegistryStore(str(database))
    store.enroll(TdxMiner.hotkey, "http://127.0.0.1:9")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "cathedral.prober",
            "--db",
            str(database),
            "--once",
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert completed.returncode != 0


# ---------------------------------------------------------------------------
# Test: non-production mode allows localhost for testing
# ---------------------------------------------------------------------------


def test_nonproduction_allows_localhost(monkeypatch, tmp_path):
    """Non-production mode permits local IP literals, allowing test miners on
    localhost."""
    server = _serve(TdxMiner2)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = TdxMiner2.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")

    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)
    probe_once(store, Policy(), production_mode=False)
    server.shutdown()

    board = store.board()
    assert board["count"] == 1
    assert board["miners"][0]["verification_status"] == "VERIFIED"


# ---------------------------------------------------------------------------
# Test: concurrent probes with fault isolation
# ---------------------------------------------------------------------------


def test_concurrent_probes_with_isolation(monkeypatch, tmp_path):
    """Multiple unreachable miners are probed concurrently. A valid TDX peer
    receives VERIFIED and is not blocked by the failures."""
    server = _serve(TdxMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    failing_hotkeys = []
    for i in range(3):
        hk = "5" + chr(ord("F") + i) * 47
        failing_hotkeys.append(hk)
        store.enroll(hk, "http://127.0.0.1:9")

    valid_hk = TdxMiner.hotkey
    store.enroll(valid_hk, f"http://127.0.0.1:{server.server_port}")

    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)

    start = time.monotonic()
    probe_once(store, Policy(), max_workers=2)
    elapsed = time.monotonic() - start

    server.shutdown()

    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}

    for hk in failing_hotkeys:
        assert statuses[hk] == "FAILED"

    assert statuses[valid_hk] == "VERIFIED"
    assert board["count"] == 1
    assert elapsed < 5.0, f"probe_once took {elapsed:.2f}s; expected < 5s with concurrency"
