"""Attestation probe loop for enrolled Cathedral miners."""

from __future__ import annotations

import argparse
import base64
import json
import time
from http.client import HTTPResponse
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

import cathedral.verify as verifier
from cathedral.common import Evidence, EvidenceKind, Policy, issue_nonce
from cathedral.enroll import RegistryStore


MAX_EVIDENCE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _read_capped(response: HTTPResponse, cap: int = MAX_EVIDENCE_BYTES) -> bytes:
    body = response.read(cap + 1)
    if len(body) > cap:
        raise ValueError("evidence response too large")
    return body


def _request_evidence(endpoint_url: str, hotkey: str, nonce: bytes) -> Evidence:
    url = urljoin(endpoint_url.rstrip("/") + "/", "v1/evidence")
    payload = json.dumps({"nonce_hex": nonce.hex(), "hotkey": hotkey}).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    opener = build_opener(NoRedirect)
    with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
        body = _read_capped(response)
    raw = json.loads(body.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evidence response must be an object")
    kind = EvidenceKind(raw["kind"])
    quote = base64.b64decode(raw["quote_b64"], validate=True)
    if len(quote) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence quote too large")
    evidence_nonce = bytes.fromhex(raw["nonce_hex"])
    if evidence_nonce != nonce:
        raise ValueError("evidence nonce mismatch")
    miner_hotkey = raw.get("miner_hotkey")
    if miner_hotkey != hotkey:
        raise ValueError("evidence hotkey mismatch")
    cert_chain = [base64.b64decode(item, validate=True) for item in raw.get("cert_chain_b64", [])]
    ssh_host_key = None
    if raw.get("ssh_host_key_b64"):
        ssh_host_key = base64.b64decode(raw["ssh_host_key_b64"], validate=True)
    return Evidence(
        kind=kind,
        quote=quote,
        nonce=evidence_nonce,
        miner_hotkey=miner_hotkey,
        cert_chain=cert_chain,
        ssh_host_key=ssh_host_key,
        composite_jwt=raw.get("composite_jwt"),
    )


def policy_from_args(args: argparse.Namespace) -> Policy:
    measurements = set(args.allow_measurement or [])
    if args.allow_measurements_file:
        with open(args.allow_measurements_file) as fh:
            measurements.update(line.strip() for line in fh if line.strip())
    return Policy(allowed_measurements=measurements, min_tcb=args.min_tcb)


def probe_once(store: RegistryStore, policy: Policy) -> None:
    for enrollment in store.enrollments():
        nonce = issue_nonce()
        try:
            evidence = _request_evidence(enrollment.endpoint_url, enrollment.hotkey, nonce)
            attested = verifier.verify(evidence, nonce, policy)
            if attested is None:
                store.record_verdict(enrollment.hotkey, None, error="verification failed")
            else:
                store.record_verdict(enrollment.hotkey, attested)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            store.record_verdict(enrollment.hotkey, None, error=type(exc).__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe enrolled Cathedral miners for TEE evidence")
    parser.add_argument("--db", default="cathedral-enroll.sqlite")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--allow-measurement", action="append", default=[])
    parser.add_argument("--allow-measurements-file")
    parser.add_argument("--min-tcb", type=int, default=0)
    args = parser.parse_args()

    store = RegistryStore(args.db)
    policy = policy_from_args(args)
    while True:
        probe_once(store, policy)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
