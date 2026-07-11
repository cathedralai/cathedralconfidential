"""Validator-side verifier + measurement policy (Phase 1).

Vendors do the cryptography (AMD KDS cert chains, Intel DCAP / Trust Authority,
NVIDIA NRAS / nvtrust); this module does policy — allowed measurements, minimum
TCB, allowed firmware — and returns an `Attested` verdict or None.
See docs/DESIGN.md §6.

Env controls for the TDX subprocess verifier:
  CATHEDRAL_TDX_VERIFY_CMD        Command (+ args) to invoke; receives quote path.
  CATHEDRAL_TDX_VERIFY_TIMEOUT    Seconds before the subprocess is killed (default 30).
  CATHEDRAL_TDX_VERIFY_MAX_OUTPUT Max bytes of stdout+stderr accepted (default 1 048 576).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import select
import shlex
import subprocess
import tempfile
import threading
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
      "platform_id": "<sybil-dedup platform key>"
    }

    The command is invoked as ``$CATHEDRAL_TDX_VERIFY_CMD <quote-file>``.
    This function then enforces Cathedral policy and binding checks.
    """

    claims = _run_tdx_verifier(evidence.quote)
    # Both flags must be the exact JSON boolean true; missing, malformed, or
    # false (including string forms and integers) all reject.
    if _claim_bool(claims, "intel_verified") is not True:
        return None
    if _claim_bool(claims, "report_data_match") is not True:
        return None

    actual_report_data = _claim_bytes(claims, "report_data")
    expected_report_data = report_data(nonce, evidence.miner_hotkey, evidence.ssh_host_key)
    if actual_report_data != expected_report_data:
        return None

    measurement = _claim_str(claims, "measurement", "mrtd", "td_measurement")
    if not measurement or measurement not in policy.allowed_measurements:
        return None

    if policy.min_tcb > 0 and _claim_str(claims, "tcb_svn") and not _claim_str(
        claims, "tcb_status", "tdx_tcb_status"
    ):
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


_DEFAULT_VERIFY_TIMEOUT = 30
_DEFAULT_MAX_OUTPUT = 1024 * 1024  # 1 MiB


def _run_tdx_verifier(quote: bytes) -> dict[str, Any]:
    """Invoke the external TDX verifier and return its parsed JSON claims.

    Enforces output cap during execution: kills subprocess if combined stdout+stderr
    exceeds max_output, preventing memory exhaustion from unbounded child output.

    Returns an empty dict on any failure so callers can treat every field as
    absent and reject accordingly.
    """
    cmd = os.environ.get("CATHEDRAL_TDX_VERIFY_CMD")
    if not cmd:
        raise NotImplementedError(
            "TDX verify requires CATHEDRAL_TDX_VERIFY_CMD "
            "(DCAP or Intel Trust Authority JSON verifier)"
        )

    try:
        timeout = int(os.environ.get("CATHEDRAL_TDX_VERIFY_TIMEOUT", str(_DEFAULT_VERIFY_TIMEOUT)))
        if timeout <= 0:
            timeout = _DEFAULT_VERIFY_TIMEOUT
    except ValueError:
        timeout = _DEFAULT_VERIFY_TIMEOUT
    try:
        max_output = int(
            os.environ.get("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", str(_DEFAULT_MAX_OUTPUT))
        )
        if max_output <= 0:
            max_output = _DEFAULT_MAX_OUTPUT
    except ValueError:
        max_output = _DEFAULT_MAX_OUTPUT

    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-") as td:
        quote_path = Path(td) / "quote.bin"
        quote_path.write_bytes(quote)
        try:
            stdout_str, stderr_str, returncode = _read_bounded_subprocess(
                [*shlex.split(cmd), str(quote_path)],
                max_output,
                timeout,
            )
        except subprocess.TimeoutExpired:
            return {}  # reject: verifier exceeded time budget

    if returncode != 0:
        return {}  # reject: verifier signalled failure

    try:
        parsed = json.loads(stdout_str)
    except json.JSONDecodeError:
        return {}  # reject: not valid JSON
    return parsed if isinstance(parsed, dict) else {}  # reject: not an object


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


def _claim_bool(claims: dict[str, Any], key: str) -> bool | None:
    """Accept only the exact JSON boolean True; reject all other forms.

    Rejects: missing, null, strings (including "true", "1", etc.), integers,
    boolean False, and any other type. Only the boolean True is accepted.
    """
    value = claims.get(key)
    # Only the exact boolean True is accepted; everything else rejects.
    return True if value is True else None


def _read_bounded_subprocess(
    cmd: list[str], max_output: int, timeout: int
) -> tuple[str, str, int]:
    """Run subprocess with bounded output capture.

    Streams stdout+stderr and kills the process if combined output exceeds
    max_output. Returns (stdout_str, stderr_str, returncode).

    Raises subprocess.TimeoutExpired if the process exceeds timeout.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    stdout_parts = []
    stderr_parts = []
    combined_bytes = 0
    exceeds_cap = threading.Event()

    def read_streams():
        """Read from stdout/stderr without deadlock; kill if cap exceeded."""
        nonlocal combined_bytes
        sentinel_size = 1024
        hard_limit = max_output + sentinel_size

        while proc.poll() is None:
            # Use select with 1s timeout to avoid blocking indefinitely
            ready_to_read, _, _ = select.select(
                [proc.stdout, proc.stderr], [], [], 1.0
            )
            for stream in ready_to_read:
                try:
                    chunk = stream.read(8192)  # Read in 8KB chunks
                    if not chunk:
                        continue
                    chunk_bytes = len(chunk.encode("utf-8"))
                    combined_bytes += chunk_bytes
                    if stream == proc.stdout:
                        stdout_parts.append(chunk)
                    else:
                        stderr_parts.append(chunk)
                    if combined_bytes > hard_limit:
                        exceeds_cap.set()
                        try:
                            proc.terminate()
                        except (ProcessLookupError, OSError):
                            pass
                        break
                except (OSError, ValueError):
                    # Stream closed or invalid
                    pass

    reader_thread = threading.Thread(target=read_streams, daemon=True)
    reader_thread.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        reader_thread.join(timeout=1)
        raise

    reader_thread.join(timeout=1)

    # Drain any remaining data
    if proc.stdout:
        try:
            remaining = proc.stdout.read()
            if remaining:
                stdout_parts.append(remaining)
        except (OSError, ValueError):
            pass
    if proc.stderr:
        try:
            remaining = proc.stderr.read()
            if remaining:
                stderr_parts.append(remaining)
        except (OSError, ValueError):
            pass

    if exceeds_cap.is_set():
        return "", "", -1

    stdout_str = "".join(stdout_parts)
    stderr_str = "".join(stderr_parts)
    return stdout_str, stderr_str, proc.returncode
