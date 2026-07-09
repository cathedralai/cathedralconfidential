from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cathedral.common import Attested, EvidenceKind, Policy, Tier
from cathedral.enroll import RegistryStore
from cathedral.prober import probe_once
from cathedral.verify.snp import parse_snp_report


FIXTURES = Path(__file__).parent / "fixtures" / "snp"
REPORT = FIXTURES / "attestation-report.bin"


def _evidence_item(kind: str, quote: bytes, payload: dict) -> dict:
    return {
        "kind": kind,
        "quote_b64": base64.b64encode(quote).decode("ascii"),
        "nonce_hex": payload["nonce_hex"],
        "miner_hotkey": payload["hotkey"],
        "cert_chain_b64": [],
    }


class SnpOnlyMiner(BaseHTTPRequestHandler):
    hotkey = "5" + "C" * 47
    hits = 0

    def do_POST(self):  # noqa: N802
        type(self).hits += 1
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        body = json.dumps(_evidence_item("sev_snp", REPORT.read_bytes(), payload)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class CompositeMiner(SnpOnlyMiner):
    hotkey = "5" + "E" * 47

    def do_POST(self):  # noqa: N802
        type(self).hits += 1
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        body = json.dumps(
            {
                "evidence": [
                    _evidence_item("sev_snp", REPORT.read_bytes(), payload),
                    _evidence_item("gpu_cc", b"gpu-quote", payload),
                ]
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GpuCcMiner(CompositeMiner):
    hotkey = "5" + "A" * 47


def _serve(handler_cls):
    handler_cls.hits = 0
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_prober_records_verified_composite_fixture_report(monkeypatch, tmp_path):
    server = _serve(CompositeMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = CompositeMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")
    parsed = parse_snp_report(REPORT.read_bytes())

    def fake_verify(evidence, nonce, policy):
        assert evidence.nonce == nonce
        assert evidence.miner_hotkey == hotkey
        if evidence.kind is EvidenceKind.SEV_SNP:
            assert evidence.quote == REPORT.read_bytes()
            return Attested(Tier.CC_CPU_SNP, parsed.chip_id, parsed.measurement, parsed.tcb.reported)
        if evidence.kind is EvidenceKind.GPU_CC:
            assert evidence.quote == b"gpu-quote"
            return Attested(Tier.CC_GPU, "gpu-chip-0", "gpu-measurement", 1)
        raise AssertionError(evidence.kind)

    monkeypatch.setattr("cathedral.prober.verifier.verify", fake_verify)
    probe_once(store, Policy())
    server.shutdown()

    board = store.board()
    assert board["count"] == 1
    assert board["miners"][0]["verification_status"] == "VERIFIED"
    assert board["miners"][0]["chip_id_prefix"] == parsed.chip_id[:16]


def test_snp_only_evidence_does_not_verify_cc_lane(monkeypatch, tmp_path):
    server = _serve(SnpOnlyMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = SnpOnlyMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")
    parsed = parse_snp_report(REPORT.read_bytes())

    def fake_verify(evidence, nonce, policy):
        assert evidence.kind is EvidenceKind.SEV_SNP
        return Attested(Tier.CC_CPU_SNP, parsed.chip_id, parsed.measurement, parsed.tcb.reported)

    monkeypatch.setattr("cathedral.prober.verifier.verify", fake_verify)
    probe_once(store, Policy())
    server.shutdown()

    board = store.board()
    assert board["count"] == 0
    assert board["miners"][0]["verification_status"] == "FAILED"


def test_gpu_cc_failure_records_failed_and_continues(monkeypatch, tmp_path):
    gpu_server = _serve(GpuCcMiner)
    snp_server = _serve(SnpOnlyMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    store.enroll(GpuCcMiner.hotkey, f"http://127.0.0.1:{gpu_server.server_port}")
    store.enroll(SnpOnlyMiner.hotkey, f"http://127.0.0.1:{snp_server.server_port}")

    def fail_if_called(evidence, nonce, policy):
        if evidence.kind is EvidenceKind.SEV_SNP:
            return Attested(Tier.CC_CPU_SNP, "chip-a", "snp-measurement", 1)
        raise NotImplementedError(f"{evidence.kind.value} unavailable")

    monkeypatch.setattr("cathedral.prober.verifier.verify", fail_if_called)
    probe_once(store, Policy())
    gpu_server.shutdown()
    snp_server.shutdown()

    board = store.board()
    statuses = {miner["hotkey"]: miner["verification_status"] for miner in board["miners"]}
    assert statuses[GpuCcMiner.hotkey] == "FAILED"
    assert statuses[SnpOnlyMiner.hotkey] == "FAILED"
    assert GpuCcMiner.hits == 1
    assert SnpOnlyMiner.hits == 1


def test_prober_unreachable_endpoint_records_failed(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "D" * 47
    store.enroll(hotkey, "http://127.0.0.1:9")

    probe_once(store, Policy())

    board = store.board()
    assert board["count"] == 0
    assert board["miners"][0]["verification_status"] == "FAILED"
