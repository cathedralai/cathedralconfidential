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
import hashlib
import hmac
import json
import logging
import os
import re
import selectors
import shlex
import signal
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

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
        # A GPU component can never produce a standalone admission verdict.
        # cathedral.gpu.verify_composite_gpu performs configured external
        # vendor verification together with the bound TDX component.
        return None
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

    In production the command is invoked as
    ``$CATHEDRAL_TDX_VERIFY_CMD <quote-file> <expected-report-data-hex>`` so
    the static verifier independently enforces Cathedral's binding. This
    function then repeats the policy and binding checks in the parent process.
    """

    expected_report_data = evidence_report_data(evidence, nonce)
    claims = _run_tdx_verifier(
        evidence.quote,
        production_mode=policy.production_ready_for_tdx,
        expected_report_data=expected_report_data,
    )
    # Both flags must be the exact JSON boolean true; missing, malformed, or
    # false (including string forms and integers) all reject.
    if _claim_bool(claims, "intel_verified") is not True:
        return None
    if _claim_bool(claims, "report_data_match") is not True:
        return None

    actual_report_data = _claim_bytes(claims, "report_data")
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
        attestation_key_id = _claim_digest_id(claims, "tdx_attestation_key_id", "tdx-ak-sha256:")
        if not pck_cert_id or not attestation_key_id:
            return None
        if not _exact_tcb_svn(tcb_svn):
            return None
        # Raw tee_tcb_svn remains an audit claim. Strict admission is based on
        # the DCAP status/advisory result, never scalar ordering of that byte
        # string. Keep the legacy scalar field at its neutral value so the
        # exact 128-bit SVN cannot overflow durable signed-receipt integers.
        tcb = 0
    else:
        if policy.min_tcb > 0 and tcb_svn and not tcb_status:
            return None
        if tcb < policy.min_tcb:
            return None
        chip_id = _bounded_identity(_claim_str(claims, "chip_id", "platform_id", "tdx_platform_id"))
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
_MAX_VERIFY_TIMEOUT = 60
_MAX_VERIFY_OUTPUT = 4 * 1024 * 1024
_MAX_PINNED_ARTIFACT_BYTES = 256 * 1024 * 1024
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SENSITIVE_ARGUMENT_RE = re.compile(
    r"(?:password|passwd|token|secret|credential|api[-_]?key)", re.IGNORECASE
)


def _bounded_int_from_env(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if 1 <= value <= maximum else default


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate verifier JSON key")
        result[key] = value
    return result


def _parse_verifier_json(body: str) -> dict[str, Any]:
    try:
        parsed = json.loads(
            body,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite verifier JSON")
            ),
        )
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _production_tdx_command(raw_command: str) -> list[str]:
    """Resolve and authenticate the complete production verifier command."""

    try:
        command = tuple(shlex.split(raw_command))
        raw_artifacts = os.environ["CATHEDRAL_TDX_VERIFY_ARTIFACTS"]
        decoded_artifacts = json.loads(raw_artifacts)
        expected_digest = os.environ["CATHEDRAL_TDX_VERIFY_DIGEST"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("production TDX verifier pinning is incomplete") from exc
    command, artifacts = _validate_production_tdx_configuration(command, decoded_artifacts)
    if not isinstance(expected_digest, str) or _DIGEST_RE.fullmatch(expected_digest) is None:
        raise ValueError("production TDX verifier configuration is invalid")
    actual_digest = _tdx_implementation_digest(command, artifacts)
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise ValueError("production TDX verifier digest does not match")
    return list(command)


def _validate_production_tdx_configuration(
    command: tuple[str, ...], artifacts_value: object
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if (
        len(command) != 1
        or any(
            not argument
            or len(argument) > 4096
            or "\x00" in argument
            or "\n" in argument
            or _SENSITIVE_ARGUMENT_RE.search(argument) is not None
            for argument in command
        )
        or not os.path.isabs(command[0])
        or not isinstance(artifacts_value, (list, tuple))
        or len(artifacts_value) != 1
        or any(
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or "\x00" in path
            or "\n" in path
            or not os.path.isabs(path)
            for path in artifacts_value
        )
        or len(set(artifacts_value)) != len(artifacts_value)
    ):
        raise ValueError("production TDX verifier configuration is invalid")
    artifacts = tuple(artifacts_value)
    if artifacts != command:
        raise ValueError("production TDX verifier must be one pinned executable")
    return command, artifacts


def _require_static_linux_elf(artifact: BinaryIO, size: int) -> None:
    """Reject interpreters, scripts, dynamic loaders, and malformed executables."""

    header = artifact.read(64)
    if len(header) != 64 or header[:4] != b"\x7fELF" or header[4:7] != b"\x02\x01\x01":
        raise OSError
    elf_type, machine = struct.unpack_from("<HH", header, 16)
    program_offset = struct.unpack_from("<Q", header, 32)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", header, 54)
    if (
        elf_type != 2
        or machine != 62
        or program_entry_size < 56
        or not 1 <= program_count <= 4096
        or program_offset < 64
        or program_offset + program_entry_size * program_count > size
    ):
        raise OSError
    artifact.seek(program_offset)
    for _ in range(program_count):
        entry = artifact.read(program_entry_size)
        if len(entry) != program_entry_size:
            raise OSError
        # PT_DYNAMIC and PT_INTERP both introduce executable code outside the
        # one digest-pinned artifact. Production accepts neither.
        if struct.unpack_from("<I", entry)[0] in {2, 3}:
            raise OSError
    artifact.seek(0)


def tdx_verifier_implementation_digest(command: tuple[str, ...], artifacts: tuple[str, ...]) -> str:
    """Validate and digest an immutable production verifier installation."""

    validated_command, validated_artifacts = _validate_production_tdx_configuration(
        command, artifacts
    )
    return _tdx_implementation_digest(validated_command, validated_artifacts)


def _tdx_implementation_digest(command: tuple[str, ...], artifacts: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(b"cathedral-tdx-verifier-implementation-v1\0")
    digest.update(
        json.dumps(
            {
                "artifacts": list(artifacts),
                "argv": list(command),
                "environment": {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                "working_directory": "/",
            },
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    for path in artifacts:
        try:
            candidate = Path(path)
            metadata = os.lstat(candidate)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022 != 0
                or metadata.st_size > _MAX_PINNED_ARTIFACT_BYTES
            ):
                raise OSError
            for ancestor in candidate.parents:
                ancestor_metadata = os.lstat(ancestor)
                if (
                    not stat.S_ISDIR(ancestor_metadata.st_mode)
                    or ancestor_metadata.st_uid != 0
                    or ancestor_metadata.st_mode & 0o022 != 0
                ):
                    raise OSError
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(candidate, flags)
            with os.fdopen(descriptor, "rb") as artifact:
                opened = os.fstat(artifact.fileno())
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError
                if path == command[0] and metadata.st_mode & 0o111 == 0:
                    raise OSError
                if path == command[0]:
                    _require_static_linux_elf(artifact, metadata.st_size)
                encoded_path = path.encode("utf-8")
                digest.update(len(encoded_path).to_bytes(4, "big"))
                digest.update(encoded_path)
                while chunk := artifact.read(1024 * 1024):
                    digest.update(chunk)
            after = os.lstat(candidate)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ):
                raise OSError
        except (OSError, UnicodeEncodeError) as exc:
            raise ValueError("production TDX verifier artifact pinning failed") from exc
    return "sha256:" + digest.hexdigest()


def preflight_tdx_verifier(policy: Policy) -> None:
    """Fail closed before production network or epoch work begins."""

    if not isinstance(policy, Policy) or not policy.production_ready_for_tdx:
        raise ValueError("production TDX requires strict signed registry policy")
    raw_command = os.environ.get("CATHEDRAL_TDX_VERIFY_CMD")
    if not raw_command:
        raise ValueError("production TDX verifier is not configured")
    _production_tdx_command(raw_command)


def _run_tdx_verifier(
    quote: bytes,
    *,
    production_mode: bool = False,
    expected_report_data: bytes | None = None,
) -> dict[str, Any]:
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

    if not isinstance(production_mode, bool):
        return {}
    production_expected_hex = ""
    if production_mode:
        if not isinstance(expected_report_data, bytes) or len(expected_report_data) != 64:
            return {}
        production_expected_hex = expected_report_data.hex()
    timeout = _bounded_int_from_env(
        "CATHEDRAL_TDX_VERIFY_TIMEOUT", _DEFAULT_VERIFY_TIMEOUT, _MAX_VERIFY_TIMEOUT
    )
    max_output = _bounded_int_from_env(
        "CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", _DEFAULT_MAX_OUTPUT, _MAX_VERIFY_OUTPUT
    )
    try:
        command = _production_tdx_command(cmd) if production_mode else shlex.split(cmd)
    except (TypeError, ValueError):
        return {}
    if not command:
        return {}

    verifier_args = [*command]

    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-") as td:
        quote_path = Path(td) / "quote.bin"
        quote_path.write_bytes(quote)
        verifier_args.append(str(quote_path))
        if production_mode:
            verifier_args.append(production_expected_hex)
        try:
            stdout_str, stderr_str, returncode = _read_bounded_subprocess(
                verifier_args,
                max_output,
                timeout,
                sanitized=production_mode,
            )
        except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired):
            return {}  # reject: verifier exceeded time budget

    if returncode != 0:
        return {}  # reject: verifier signalled failure

    return _parse_verifier_json(stdout_str)


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
    if (
        not value
        or len(value) > 512
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
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
    cmd: list[str],
    max_output: int,
    timeout: int,
    *,
    sanitized: bool = False,
    start_new_session: bool = True,
) -> tuple[str, str, int]:
    """Run a subprocess with a hard combined-output byte cap and wall-clock timeout.

    Reads both stdout and stderr in the calling thread using the platform's
    scalable default selector and
    os.read so there is no race between a drain thread and the main path.
    Binary pipes prevent codec-buffering surprises.

    Enforcement guarantees:
    - At most max_output bytes are stored; the very read that pushes combined
      past max_output is discarded and triggers immediate kill+reap.
    - The post-exit pipe drain shares the same combined counter, so a fast
      child that writes and exits cannot bypass the cap.
    - Wall-clock timeout fires inside the selector; kill and reap happen before
      raising TimeoutExpired.

    Returns (stdout_str, stderr_str, returncode).
    Returns ("", "", -1) if the byte cap is exceeded.
    Raises subprocess.TimeoutExpired if the process exceeds timeout seconds.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=start_new_session,
        cwd="/" if sanitized else None,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"} if sanitized else None,
    )

    stdout_buf: list[bytes] = []
    stderr_buf: list[bytes] = []
    combined = 0
    deadline = time.monotonic() + timeout

    out_fd = proc.stdout.fileno()
    err_fd = proc.stderr.fileno()
    fd_to_buf: dict[int, list[bytes]] = {out_fd: stdout_buf, err_fd: stderr_buf}
    cap_exceeded = False
    selector = selectors.DefaultSelector()
    try:
        selector.register(out_fd, selectors.EVENT_READ)
        selector.register(err_fd, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_subprocess(proc, process_group=start_new_session)
                raise subprocess.TimeoutExpired(cmd, timeout)
            try:
                readable = selector.select(min(remaining, 1.0))
            except OSError:
                _terminate_subprocess(proc, process_group=start_new_session)
                return "", "", -1
            for key, _mask in readable:
                fd = int(key.fd)
                try:
                    data = os.read(fd, 65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    data = b""
                if not data:
                    selector.unregister(fd)
                    continue
                combined += len(data)
                if combined > max_output:
                    cap_exceeded = True
                    break
                fd_to_buf[fd].append(data)
            if cap_exceeded:
                break
    finally:
        selector.close()

    if cap_exceeded:
        _terminate_subprocess(proc, process_group=start_new_session)
        proc.stdout.close()
        proc.stderr.close()
        return "", "", -1

    # Both pipes are at EOF; close them and wait for the process to exit.
    proc.stdout.close()
    proc.stderr.close()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _terminate_subprocess(proc, process_group=start_new_session)
        raise subprocess.TimeoutExpired(cmd, timeout)
    try:
        proc.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        _terminate_subprocess(proc, process_group=start_new_session)
        raise

    # A verifier may close its pipes, spawn a background descendant, and exit.
    # The group leader is already reaped here; kill any remaining members so a
    # successful or failed verification cannot leave unbounded helper processes.
    if start_new_session:
        _terminate_subprocess(proc, process_group=True)

    return (
        b"".join(stdout_buf).decode("utf-8"),
        b"".join(stderr_buf).decode("utf-8"),
        proc.returncode,
    )


def _terminate_subprocess(process: subprocess.Popen[bytes], *, process_group: bool) -> None:
    if process_group:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.wait()
