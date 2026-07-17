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
import logging
import json
import os
import select
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from cathedral.assurance import attestation_claims
from cathedral.common import (
    TDX_TCB_STATUSES,
    Attested,
    Evidence,
    EvidenceKind,
    Policy,
    Tier,
    evidence_report_data,
)
from cathedral.verify.snp import verify_snp


LOGGER = logging.getLogger(__name__)


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

    expected = evidence_report_data(evidence, nonce)
    _ = expected  # bound-in check happens against the parsed quote in Phase 1

    if evidence.kind is EvidenceKind.SEV_SNP:
        return verify_snp(evidence, nonce, policy)
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
    expected_report_data = evidence_report_data(evidence, nonce)
    if actual_report_data != expected_report_data:
        return None

    measurement = (
        _claim_exact_str(claims, "measurement")
        if policy.tdx_strict
        else _claim_str(claims, "measurement", "mrtd", "td_measurement")
    )
    if not measurement or measurement not in policy.allowed_measurements:
        return None

    tcb_svn = _claim_exact_str(claims, "tcb_svn") or None
    tcb = _claim_int(claims, "tcb", "tcb_svn", default=-1)
    tcb_status = (
        _claim_exact_str(claims, "tcb_status")
        if policy.tdx_strict
        else _claim_exact_str(claims, "tcb_status", "tdx_tcb_status")
    ) or None
    advisory_ids = _claim_str_list(claims, "advisory_ids")
    debug_enabled = _claim_exact_bool(claims, "debug_enabled")
    collateral_current = _claim_exact_bool(claims, "collateral_current")
    platform_identity_kind = _claim_exact_str(claims, "platform_identity_kind") or None

    if policy.tdx_strict:
        if tcb_status not in TDX_TCB_STATUSES or tcb_status == "Revoked":
            return None
        if tcb_status not in policy.tdx_allowed_tcb_statuses:
            return None
        if advisory_ids is None:
            return None
        if tcb_status != "UpToDate" and not advisory_ids:
            return None
        if any(advisory not in policy.tdx_allowed_advisories for advisory in advisory_ids):
            return None
        if debug_enabled is not False:
            return None
        if collateral_current is not True:
            return None
        if platform_identity_kind != "stable":
            return None
        if _claim_exact_bool(claims, "platform_identity_verified") is not True:
            return None
        if _claim_exact_bool(claims, "claims_bound_to_quote") is not True:
            return None
        chip_id = _claim_digest_id(claims, "stable_platform_id", "tdx-platform-sha256:")
        if not chip_id or _claim_exact_str(claims, "platform_id") != chip_id:
            return None
        pck_cert_id = _claim_digest_id(claims, "tdx_pck_cert_id", "tdx-pck-cert-sha256:")
        attestation_key_id = _claim_digest_id(
            claims, "tdx_attestation_key_id", "tdx-ak-sha256:"
        )
        if not pck_cert_id or not attestation_key_id:
            return None
        if not _exact_tcb_svn(tcb_svn):
            return None
        # Raw tee_tcb_svn remains an audit claim. Strict admission is based on
        # the DCAP status/advisory result, never scalar ordering of that byte string.
        tcb = int(tcb_svn, 16)
    else:
        if policy.min_tcb > 0 and tcb_svn and not tcb_status:
            return None
        if tcb < policy.min_tcb:
            return None
        chip_id = _bounded_identity(
            _claim_str(claims, "chip_id", "platform_id", "tdx_platform_id")
        )
        if not chip_id:
            return None
        pck_cert_id = _claim_exact_str(claims, "tdx_pck_cert_id") or None
        attestation_key_id = _claim_exact_str(claims, "tdx_attestation_key_id") or None
        LOGGER.warning(
            "accepted TDX evidence in compatibility policy mode; strict typed claims "
            "and stable platform identity were not enforced"
        )

    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=chip_id,
        measurement=measurement,
        tcb=tcb,
        tcb_status=tcb_status,
        advisory_ids=advisory_ids or (),
        debug_enabled=debug_enabled,
        collateral_current=collateral_current,
        platform_identity_kind=platform_identity_kind,
        tcb_svn=tcb_svn,
        pck_cert_id=pck_cert_id,
        attestation_key_id=attestation_key_id,
        policy_mode="strict" if policy.tdx_strict else "compatibility",
        assurance=attestation_claims(evidence.quote, policy),
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


def _claim_exact_str(claims: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = claims.get(key)
        if isinstance(value, str):
            return value
        if value is not None:
            return ""
    return ""


def _claim_str_list(claims: dict[str, Any], key: str) -> tuple[str, ...] | None:
    value = claims.get(key)
    if not isinstance(value, list) or len(value) > 64:
        return None
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > 128
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in item)
        for item in value
    ):
        return None
    if len(set(value)) != len(value):
        return None
    return tuple(sorted(value))


def _claim_exact_bool(claims: dict[str, Any], key: str) -> bool | None:
    value = claims.get(key)
    return value if isinstance(value, bool) else None


def _bounded_identity(value: str) -> str:
    if not value or len(value) > 512 or any(
        ord(char) < 0x21 or ord(char) == 0x7F for char in value
    ):
        return ""
    return value


def _claim_digest_id(claims: dict[str, Any], key: str, prefix: str) -> str:
    value = _claim_exact_str(claims, key)
    digest = value.removeprefix(prefix)
    if not value.startswith(prefix) or len(digest) != 64:
        return ""
    if digest != digest.lower():
        return ""
    if any(character not in "0123456789abcdef" for character in digest):
        return ""
    return value


def _exact_tcb_svn(value: str | None) -> bool:
    if value is None or len(value) != 32:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _claim_int(claims: dict[str, Any], *keys: str, default: int) -> int:
    for key in keys:
        value = claims.get(key)
        if value is None:
            continue
        if isinstance(value, int) and not isinstance(value, bool):
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
    """Run a subprocess with a hard combined-output byte cap and wall-clock timeout.

    Reads both stdout and stderr in the calling thread using select(2) and
    os.read so there is no race between a drain thread and the main path.
    Binary pipes prevent codec-buffering surprises.

    Enforcement guarantees:
    - At most max_output bytes are stored; the very read that pushes combined
      past max_output is discarded and triggers immediate kill+reap.
    - The post-exit pipe drain shares the same combined counter, so a fast
      child that writes and exits cannot bypass the cap.
    - Wall-clock timeout fires inside select(); kill and reap happen before
      raising TimeoutExpired.

    Returns (stdout_str, stderr_str, returncode).
    Returns ("", "", -1) if the byte cap is exceeded.
    Raises subprocess.TimeoutExpired if the process exceeds timeout seconds.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout_buf: list[bytes] = []
    stderr_buf: list[bytes] = []
    combined = 0
    deadline = time.monotonic() + timeout

    out_fd = proc.stdout.fileno()
    err_fd = proc.stderr.fileno()
    fd_to_buf: dict[int, list[bytes]] = {out_fd: stdout_buf, err_fd: stderr_buf}
    open_fds: set[int] = {out_fd, err_fd}
    cap_exceeded = False

    while open_fds:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                proc.kill()
            except OSError:
                pass
            proc.stdout.close()
            proc.stderr.close()
            proc.wait()
            raise subprocess.TimeoutExpired(cmd, timeout)

        try:
            readable, _, _ = select.select(list(open_fds), [], [], min(remaining, 1.0))
        except OSError:
            break

        for fd in readable:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if not data:
                open_fds.discard(fd)
                continue
            combined += len(data)
            if combined > max_output:
                cap_exceeded = True
                break
            fd_to_buf[fd].append(data)

        if cap_exceeded:
            break

    if cap_exceeded:
        try:
            proc.kill()
        except OSError:
            pass
        proc.stdout.close()
        proc.stderr.close()
        proc.wait()
        return "", "", -1

    # Both pipes are at EOF; close them and wait for the process to exit.
    proc.stdout.close()
    proc.stderr.close()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
        raise subprocess.TimeoutExpired(cmd, timeout)
    try:
        proc.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
        raise

    return (
        b"".join(stdout_buf).decode("utf-8", errors="replace"),
        b"".join(stderr_buf).decode("utf-8", errors="replace"),
        proc.returncode,
    )
