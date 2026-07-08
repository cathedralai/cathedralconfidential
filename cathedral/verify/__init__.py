"""Validator-side verifier + measurement policy (Phase 1).

Vendors do the cryptography (AMD KDS cert chains, Intel DCAP / Trust Authority,
NVIDIA NRAS / nvtrust); this module does policy — allowed measurements, minimum
TCB, allowed firmware — and returns an `Attested` verdict or None.
See docs/DESIGN.md §6.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier, report_data


def verify(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    """Verify one piece of evidence against the policy. None => rejected.

    Steps (per vendor, Phase 1):
      1. vendor-verify the quote's signature + cert chain (KDS / DCAP / NRAS)
      2. check REPORT_DATA == report_data(nonce, evidence.miner_hotkey, ...)
         — freshness + hotkey ownership (defeats evidence relay)
      3. check measurement in policy.allowed_measurements and tcb >= min_tcb
      4. extract chip_id (SNP CHIP_ID / TDX platform id / GPU UUID) for
         free sybil defense (one machine -> one UID)
    """

    expected = report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)
    _ = expected  # bound-in check happens against the parsed quote in Phase 1

    if evidence.kind is EvidenceKind.SEV_SNP:
        raise NotImplementedError("SNP verify — Phase 1 (snpguest verify + KDS)")
    if evidence.kind is EvidenceKind.TDX:
        return _verify_tdx(evidence, nonce, policy)
    if evidence.kind is EvidenceKind.GPU_CC:
        raise NotImplementedError("GPU CC verify — Phase 1 (NRAS / nvtrust + composite JWT)")
    return None


def _verify_tdx(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    """TDX verifier adapter.

    Cathedral does not hand-roll Intel quote verification. Set
    ``CATHEDRAL_TDX_VERIFY_CMD`` to a verifier that performs DCAP or Trust
    Authority validation and prints JSON claims:

    {
      "report_data": "<hex or base64>",
      "measurement": "<MRTD or policy measurement>",
      "tcb": 1,
      "platform_id": "<stable physical platform id>"
    }

    The command is invoked as ``$CATHEDRAL_TDX_VERIFY_CMD <quote-file>``.
    This function then enforces Cathedral policy and binding checks.
    """

    claims = _run_tdx_verifier(evidence.quote)
    actual_report_data = _claim_bytes(claims, "report_data")
    expected_report_data = report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)
    if actual_report_data != expected_report_data:
        return None

    measurement = _claim_str(claims, "measurement", "mrtd", "td_measurement")
    if not measurement or measurement not in policy.allowed_measurements:
        return None

    tcb = _claim_int(claims, "tcb", "tcb_svn", default=-1)
    if tcb < policy.min_tcb:
        return None

    chip_id = _claim_str(claims, "chip_id", "platform_id", "tdx_platform_id")
    if not chip_id:
        return None

    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=chip_id,
        measurement=measurement,
        tcb=tcb,
    )


def _run_tdx_verifier(quote: bytes) -> dict[str, Any]:
    cmd = os.environ.get("CATHEDRAL_TDX_VERIFY_CMD")
    if not cmd:
        raise NotImplementedError(
            "TDX verify requires CATHEDRAL_TDX_VERIFY_CMD "
            "(DCAP or Intel Trust Authority JSON verifier)"
        )

    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-") as td:
        quote_path = Path(td) / "quote.bin"
        quote_path.write_bytes(quote)
        proc = subprocess.run(
            [*shlex.split(cmd), str(quote_path)],
            check=False,
            capture_output=True,
            text=True,
        )

    if proc.returncode != 0:
        return {}
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _claim_bytes(claims: dict[str, Any], key: str) -> bytes:
    value = claims.get(key)
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return b""

    text = value.strip()
    if text.startswith("0x"):
        text = text[2:]
    try:
        return bytes.fromhex(text)
    except ValueError:
        pass
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _claim_str(claims: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = claims.get(key)
        if value is not None:
            return str(value)
    return ""


def _claim_int(claims: dict[str, Any], *keys: str, default: int) -> int:
    for key in keys:
        value = claims.get(key)
        if value is None:
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                continue
    return default
