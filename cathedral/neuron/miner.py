"""Miner neuron (Phase 1+).

Inverted trust topology: the miner *serves* attestation on request and runs
lane work; the validator never SSHes in.
See docs/DESIGN.md §4, §9.

    register on SN39  ->  serve /evidence + /info  ->  subscribe to lanes  ->  do work

Hardware-free testable core: ``MockMiner`` serves MOCK evidence (the real
REPORT_DATA binding + policy check, no vendor crypto) and does real SAT work.
The MOCK boundary is the only substitution — the SAT solve/certify path is the
real Phase-2 code. ``main`` (real registration + hardware collectors) stays a
Phase-1 stub with clear markers.
"""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass
from typing import Any
from wsgiref.simple_server import make_server

from cathedral.attest import collect_gpu_cc, collect_snp
from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier
from cathedral.lanes.sat import solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.verify.mock import mock_evidence, verify_mock


@dataclass
class MockMiner:
    """A hardware-free miner: an identity + a mock TEE + a SAT worker.

    Phase-1 swap-in: replace ``serve_evidence`` with a real attestation collector
    (cathedral.attest.collect_*) served over an authenticated axon endpoint, and
    let the validator run the vendor-crypto ``cathedral.verify.verify`` instead of
    ``verify_mock``.
    """

    uid: str
    hotkey: str
    tier: Tier = Tier.CC_CPU_SNP
    kind: EvidenceKind = EvidenceKind.SEV_SNP
    chip_id: str = "mock-chip-0"
    measurement: str = "mock-measurement-0"
    tcb: int = 1

    def serve_evidence(self, nonce: bytes, policy: Policy) -> Attested | None:
        """Answer a validator challenge: build mock evidence bound to the nonce
        and this hotkey, then return the verifier's verdict (None if rejected).

        The MOCK verifier performs the *real* REPORT_DATA binding + measurement/
        TCB policy checks (docs/DESIGN.md §6); only the vendor crypto is skipped.
        """

        evidence = mock_evidence(
            nonce,
            self.hotkey,
            kind=self.kind,
            tier=self.tier,
            chip_id=self.chip_id,
            measurement=self.measurement,
            tcb=self.tcb,
        )
        return verify_mock(evidence, nonce, policy)

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        """Solve a dispatched SAT instance and return a self-certifying result.

        SAT: a satisfying assignment is the certificate (checkable in µs); UNSAT
        is claimed with no assignment (DRAT proof in production).
        """

        assignment = solve_sat(item.instance)
        if assignment is None:
            return SatCertificate(satisfiable=False, assignment=None, work_units=1.0)
        return SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=float(len(item.instance.clauses)),
        )


class EvidenceApp:
    """Miner-side HTTP evidence endpoint served to validators/probers."""

    def __init__(self, hotkey: str) -> None:
        self.hotkey = hotkey

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        try:
            if environ.get("REQUEST_METHOD") != "POST" or environ.get("PATH_INFO") != "/v1/evidence":
                return self._json(start_response, 404, {"error": "not found"})
            try:
                length = int(environ.get("CONTENT_LENGTH") or "0")
            except ValueError as exc:
                raise ValueError("invalid content length") from exc
            if length <= 0 or length > 16 * 1024:
                raise ValueError("invalid body size")
            payload = json.loads(environ["wsgi.input"].read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("json body must be an object")
            nonce = bytes.fromhex(payload["nonce_hex"])
            requested_hotkey = payload.get("hotkey")
            if requested_hotkey is not None and requested_hotkey != self.hotkey:
                raise ValueError("hotkey mismatch")
            evidences = [
                collect_snp(nonce, self.hotkey),
                collect_gpu_cc(nonce, self.hotkey),
            ]
            body = {"evidence": [self._evidence_json(evidence) for evidence in evidences]}
            return self._json(start_response, 200, body)
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            return self._json(start_response, 400, {"error": str(exc)})
        except Exception as exc:
            return self._json(start_response, 503, {"error": str(exc)})

    @staticmethod
    def _json(start_response: Any, status: int, payload: dict[str, Any]) -> list[bytes]:
        reason = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            503: "Service Unavailable",
        }.get(status, "OK")
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        start_response(
            f"{status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]

    @staticmethod
    def _evidence_json(evidence: Evidence) -> dict[str, Any]:
        return {
            "kind": evidence.kind.value,
            "quote_b64": base64.b64encode(evidence.quote).decode("ascii"),
            "nonce_hex": evidence.nonce.hex(),
            "miner_hotkey": evidence.miner_hotkey,
            "cert_chain_b64": [
                base64.b64encode(cert).decode("ascii") for cert in evidence.cert_chain
            ],
            "ssh_host_key_b64": (
                base64.b64encode(evidence.ssh_host_key).decode("ascii")
                if evidence.ssh_host_key is not None
                else None
            ),
            "composite_jwt": evidence.composite_jwt,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve Cathedral miner TEE evidence")
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()

    app = EvidenceApp(args.hotkey)
    with make_server(args.host, args.port, app) as server:
        print(f"serving miner evidence on http://{args.host}:{args.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
