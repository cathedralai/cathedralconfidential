"""Attestation probe loop for enrolled Cathedral miners."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import time
from http.client import HTTPResponse
from typing import Any
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

import cathedral.verify as verifier
from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier, issue_nonce
from cathedral.enroll import RegistryStore


MAX_EVIDENCE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5
LOGGER = logging.getLogger(__name__)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _read_capped(response: HTTPResponse, cap: int = MAX_EVIDENCE_BYTES) -> bytes:
    body = response.read(cap + 1)
    if len(body) > cap:
        raise ValueError("evidence response too large")
    return body


def _parse_evidence_item(raw: Any, hotkey: str, nonce: bytes) -> Evidence:
    if not isinstance(raw, dict):
        raise ValueError("evidence item must be an object")
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


def _request_evidence(endpoint_url: str, hotkey: str, nonce: bytes) -> list[Evidence]:
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
    if isinstance(raw.get("evidence"), list):
        items = raw["evidence"]
    elif isinstance(raw.get("evidence_items"), list):
        items = raw["evidence_items"]
    else:
        items = [raw]
    if not items or len(items) > 8:
        raise ValueError("evidence bundle size invalid")
    return [_parse_evidence_item(item, hotkey, nonce) for item in items]


def policy_from_args(args: argparse.Namespace) -> Policy:
    measurements = set(args.allow_measurement or [])
    if args.allow_measurements_file:
        with open(args.allow_measurements_file) as fh:
            measurements.update(line.strip() for line in fh if line.strip())
    return Policy(allowed_measurements=measurements, min_tcb=args.min_tcb)


def verify_cc_evidence_bundle(
    evidences: list[Evidence],
    nonce: bytes,
    policy: Policy,
) -> Attested | None:
    """Enrollment requires both a verified SNP guest and verified GPU CC evidence.

    GPU verification is intentionally still fail-closed. Until the NVIDIA NRAS
    or local verifier is wired in, ``verifier.verify`` returns ``None`` for
    GPU_CC evidence and this bundle cannot produce an admission verdict.
    """

    snp = next((evidence for evidence in evidences if evidence.kind is EvidenceKind.SEV_SNP), None)
    gpu = next((evidence for evidence in evidences if evidence.kind is EvidenceKind.GPU_CC), None)
    if snp is None or gpu is None:
        return None

    snp_attested = verifier.verify(snp, nonce, policy)
    gpu_attested = verifier.verify(gpu, nonce, policy)
    if (
        snp_attested is None
        or gpu_attested is None
        or snp_attested.verification_status != "VERIFIED"
        or gpu_attested.verification_status != "VERIFIED"
    ):
        return None

    measurement = hashlib.sha256(
        f"snp:{snp_attested.measurement}\ngpu:{gpu_attested.measurement}".encode("utf-8")
    ).hexdigest()
    return Attested(
        tier=Tier.CC_GPU,
        chip_id=snp_attested.chip_id,
        measurement=measurement,
        tcb=min(snp_attested.tcb, gpu_attested.tcb),
    )


def probe_once(store: RegistryStore, policy: Policy) -> None:
    for enrollment in store.enrollments():
        nonce = issue_nonce()
        try:
            evidences = _request_evidence(enrollment.endpoint_url, enrollment.hotkey, nonce)
            attested = verify_cc_evidence_bundle(evidences, nonce, policy)
            if attested is None:
                store.record_verdict(enrollment.hotkey, None, error="verification failed")
            else:
                store.record_verdict(enrollment.hotkey, attested)
        except Exception as exc:
            try:
                store.record_verdict(enrollment.hotkey, None, error=type(exc).__name__)
            except Exception:
                LOGGER.exception("failed to record probe failure for hotkey %s", enrollment.hotkey)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
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
        try:
            probe_once(store, policy)
        except Exception:
            LOGGER.exception("probe pass failed")
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
