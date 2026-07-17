"""Prober tests: TDX-CPU launch path, fault isolation, production gates.

No SNP fixtures or cathedral.verify.snp dependency. All attestation evidence
is TDX, verified via a monkeypatched verifier returning Attested(CC_CPU_TDX).
GPU composite path remains fail-closed (no GPU verifier wired in).
"""

from __future__ import annotations

import base64
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from cathedral.common import Attested, EvidenceKind, Policy, Tier
from cathedral.enroll import RegistryStore
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
    args = argparse.Namespace(
        allow_measurement=["m"], allow_measurements_file=None, min_tcb=0
    )

    policy = policy_from_args(args)

    assert policy.tdx_strict is False
    assert policy.tdx_allowed_tcb_statuses == {"UpToDate"}


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
        body = json.dumps(
            _evidence_item("tdx", TDX_QUOTE, payload)
        ).encode("utf-8")
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
        )
    return None


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


def test_production_mode_rejects_non_global_ip_before_network(tmp_path):
    """In production_mode, local IP literals are rejected before the opener
    is ever invoked."""
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    policy = Policy()

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

    probe_once(store, policy, opener=mock_opener, production_mode=True)

    assert not opener_called, "opener was invoked for a local IP literal in production mode"

    board = store.board()
    assert board["count"] == 0
    for miner in board["miners"]:
        assert miner["verification_status"] == "FAILED"


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
