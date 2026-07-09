from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cathedral.common import Attested, Policy, Tier
from cathedral.enroll import RegistryStore
from cathedral.prober import probe_once
from cathedral.verify.snp import parse_snp_report


FIXTURES = Path(__file__).parent / "fixtures" / "snp"
REPORT = FIXTURES / "attestation-report.bin"


class FixtureMiner(BaseHTTPRequestHandler):
    hotkey = "5" + "C" * 47

    def do_POST(self):  # noqa: N802
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        body = json.dumps(
            {
                "kind": "sev_snp",
                "quote_b64": base64.b64encode(REPORT.read_bytes()).decode("ascii"),
                "nonce_hex": payload["nonce_hex"],
                "miner_hotkey": payload["hotkey"],
                "cert_chain_b64": [],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_prober_records_verified_fixture_report(monkeypatch, tmp_path):
    server = _serve(FixtureMiner)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = FixtureMiner.hotkey
    store.enroll(hotkey, f"http://127.0.0.1:{server.server_port}")
    parsed = parse_snp_report(REPORT.read_bytes())

    def fake_verify(evidence, nonce, policy):
        assert evidence.quote == REPORT.read_bytes()
        assert evidence.nonce == nonce
        assert evidence.miner_hotkey == hotkey
        return Attested(Tier.CC_CPU_SNP, parsed.chip_id, parsed.measurement, parsed.tcb.reported)

    monkeypatch.setattr("cathedral.prober.verifier.verify", fake_verify)
    probe_once(store, Policy())
    server.shutdown()

    board = store.board()
    assert board["count"] == 1
    assert board["miners"][0]["verification_status"] == "VERIFIED"
    assert board["miners"][0]["chip_id_prefix"] == parsed.chip_id[:16]


def test_prober_unreachable_endpoint_records_failed(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "D" * 47
    store.enroll(hotkey, "http://127.0.0.1:9")

    probe_once(store, Policy())

    board = store.board()
    assert board["count"] == 0
    assert board["miners"][0]["verification_status"] == "FAILED"
