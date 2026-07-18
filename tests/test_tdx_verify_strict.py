"""Contract: TDX verifier requires exact boolean True for intel_verified and
report_data_match; timeout, oversized output, nonzero exit, and malformed JSON
all reject without hanging.

These tests supplement test_verify_tdx.py which covers measurement/TCB/binding
policy. This file focuses on subprocess safety and flag strictness.

Env knobs exercised:
  CATHEDRAL_TDX_VERIFY_TIMEOUT    seconds before the subprocess is killed
  CATHEDRAL_TDX_VERIFY_MAX_OUTPUT max bytes of stdout+stderr accepted
"""

from __future__ import annotations

import json
import io
import os
import resource
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta

import pytest

from cathedral.common import Evidence, EvidenceKind, Policy, issue_nonce, report_data
from cathedral.verify import (
    _read_bounded_subprocess,
    _require_static_linux_elf,
    _validate_production_tdx_configuration,
    verify,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _fake_verifier(tmp_path, body: str) -> str:
    """Write a tiny Python script that prints *body* and return CMD string."""
    script = tmp_path / "fake_tdx_verifier.py"
    script.write_text(
        f"""
from __future__ import annotations
import sys
# consume the quote-file argument so the interface matches
_quote = open(sys.argv[-1], "rb").read()
{body}
""".lstrip()
    )
    return f"{sys.executable} {script}"


def _good_claims_body(rd_hex: str, measurement: str, platform_id: str, tcb: int = 0) -> str:
    """Python snippet that prints a fully valid JSON claims object."""
    return (
        f"import json\n"
        f"print(json.dumps({{"
        f'"intel_verified": True, '
        f'"report_data_match": True, '
        f'"report_data": "{rd_hex}", '
        f'"measurement": "{measurement}", '
        f'"tcb": {tcb}, '
        f'"platform_id": "{platform_id}"'
        f"}}))"
    )


def _make_evidence(nonce: bytes, hotkey: str) -> Evidence:
    return Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)


def _policy(measurement: str) -> Policy:
    return Policy(allowed_measurements={measurement})


def _production_policy(measurement: str) -> Policy:
    policy = Policy(
        allowed_measurements={measurement},
        tdx_strict=True,
        registry_release=7,
        registry_digest="sha256:" + "7" * 64,
        registry_profile_ids=("cpu-tdx-v1",),
    )
    object.__setattr__(policy, "_registry_verified", True)
    object.__setattr__(policy, "_registry_valid_from", datetime.now(UTC) - timedelta(days=1))
    object.__setattr__(policy, "_registry_valid_until", datetime.now(UTC) + timedelta(days=1))
    return policy


# ---------------------------------------------------------------------------
# Exact-True flag requirements
# ---------------------------------------------------------------------------


def test_missing_intel_verified_rejects(tmp_path, monkeypatch):
    """Verifier JSON omitting intel_verified must reject (fails closed)."""
    nonce = issue_nonce()
    hotkey = "hk-strict-1"
    rd_hex = report_data(nonce, hotkey).hex()
    body = (
        f"import json\n"
        f'print(json.dumps({{"report_data_match": True, "report_data": "{rd_hex}", '
        f'"measurement": "m1", "tcb": 0, "platform_id": "p1"}}))'
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_missing_report_data_match_rejects(tmp_path, monkeypatch):
    """Verifier JSON omitting report_data_match must reject (fails closed)."""
    nonce = issue_nonce()
    hotkey = "hk-strict-2"
    rd_hex = report_data(nonce, hotkey).hex()
    body = (
        f"import json\n"
        f'print(json.dumps({{"intel_verified": True, "report_data": "{rd_hex}", '
        f'"measurement": "m1", "tcb": 0, "platform_id": "p1"}}))'
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_intel_verified_null_rejects(tmp_path, monkeypatch):
    """JSON null for intel_verified must reject."""
    nonce = issue_nonce()
    hotkey = "hk-strict-3"
    rd_hex = report_data(nonce, hotkey).hex()
    body = (
        f"import json\n"
        f'print(json.dumps({{"intel_verified": None, "report_data_match": True, '
        f'"report_data": "{rd_hex}", "measurement": "m1", "tcb": 0, "platform_id": "p1"}}))'
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_intel_verified_integer_one_rejects(tmp_path, monkeypatch):
    """Integer 1 for intel_verified must reject — only exact bool True accepted."""
    nonce = issue_nonce()
    hotkey = "hk-strict-4"
    rd_hex = report_data(nonce, hotkey).hex()
    body = (
        f"import json\n"
        f'print(json.dumps({{"intel_verified": 1, "report_data_match": True, '
        f'"report_data": "{rd_hex}", "measurement": "m1", "tcb": 0, "platform_id": "p1"}}))'
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_report_data_match_integer_one_rejects(tmp_path, monkeypatch):
    """Integer 1 for report_data_match must reject."""
    nonce = issue_nonce()
    hotkey = "hk-strict-5"
    rd_hex = report_data(nonce, hotkey).hex()
    body = (
        f"import json\n"
        f'print(json.dumps({{"intel_verified": True, "report_data_match": 1, '
        f'"report_data": "{rd_hex}", "measurement": "m1", "tcb": 0, "platform_id": "p1"}}))'
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_both_flags_false_rejects(tmp_path, monkeypatch):
    """Both flags explicitly False must reject."""
    nonce = issue_nonce()
    hotkey = "hk-strict-6"
    rd_hex = report_data(nonce, hotkey).hex()
    body = (
        f"import json\n"
        f'print(json.dumps({{"intel_verified": False, "report_data_match": False, '
        f'"report_data": "{rd_hex}", "measurement": "m1", "tcb": 0, "platform_id": "p1"}}))'
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


# ---------------------------------------------------------------------------
# Subprocess safety — timeout
# ---------------------------------------------------------------------------


def test_verifier_timeout_rejects_without_hanging(tmp_path, monkeypatch):
    """A verifier that exceeds the timeout must be rejected, not hung."""
    nonce = issue_nonce()
    hotkey = "hk-timeout-1"
    # Verifier sleeps 10 s; timeout is 1 s.
    body = "import time; time.sleep(10)"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_TIMEOUT", "1")

    start = time.monotonic()
    result = verify(_make_evidence(nonce, hotkey), nonce, _policy("m1"))
    elapsed = time.monotonic() - start

    assert result is None
    # Must return well within the sleep duration — allow generous headroom.
    assert elapsed < 8, f"verify() blocked for {elapsed:.1f}s (expected < 8)"


def test_bounded_reader_supports_pipe_descriptors_above_fd_setsize():
    soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit < 1200:
        pytest.skip("process descriptor limit is too small for the regression")
    descriptors: list[int] = []
    try:
        while not descriptors or descriptors[-1] <= 1100:
            descriptors.append(os.open(os.devnull, os.O_RDONLY))
        stdout, stderr, returncode = _read_bounded_subprocess(
            [sys.executable, "-c", "print('selector-ok')"],
            4096,
            5,
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    assert (stdout, stderr, returncode) == ("selector-ok\n", "", 0)


def test_bounded_reader_kills_descendants_that_keep_pipes_open():
    program = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "print('parent-exit')"
    )
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _read_bounded_subprocess(
            [sys.executable, "-c", program],
            4096,
            1,
        )
    assert time.monotonic() - started < 5


def test_bounded_reader_kills_descendants_after_parent_exits():
    program = (
        "import subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "print(child.pid,flush=True); raise SystemExit(1)"
    )
    stdout, _stderr, returncode = _read_bounded_subprocess([sys.executable, "-c", program], 4096, 5)
    descendant_pid = int(stdout.strip())
    assert returncode == 1
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        os.kill(descendant_pid, 9)
        pytest.fail("verifier descendant survived parent completion")


def test_duplicate_verifier_json_keys_reject_last_value_bypass(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hk-duplicate-json"
    report = report_data(nonce, hotkey).hex()
    body = (
        "print('{'"
        f'\'"report_data":"{report}",\''
        '\'"measurement":"m1","tcb":0,\''
        '\'"platform_id":"platform",\''
        '\'"intel_verified":false,"intel_verified":true,\''
        "'\"report_data_match\":true}')"
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_signed_policy_requires_pinned_production_verifier(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hk-unpinned-production"
    report = report_data(nonce, hotkey).hex()
    body = _good_claims_body(report, "m1", "platform")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    monkeypatch.delenv("CATHEDRAL_TDX_VERIFY_ARTIFACTS", raising=False)
    monkeypatch.delenv("CATHEDRAL_TDX_VERIFY_DIGEST", raising=False)
    assert verify(_make_evidence(nonce, hotkey), nonce, _production_policy("m1")) is None


def test_production_verifier_rejects_interpreter_or_fixed_arguments():
    with pytest.raises(ValueError, match="configuration is invalid"):
        _validate_production_tdx_configuration(
            (sys.executable, "/opt/cathedral/tdx_verify_json.py"),
            [sys.executable, "/opt/cathedral/tdx_verify_json.py"],
        )


def test_production_verifier_requires_static_x86_64_elf():
    executable = bytearray(120)
    executable[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", executable, 16, 2, 62)
    struct.pack_into("<Q", executable, 32, 64)
    struct.pack_into("<HH", executable, 54, 56, 1)
    struct.pack_into("<I", executable, 64, 1)
    _require_static_linux_elf(io.BytesIO(executable), len(executable))

    struct.pack_into("<I", executable, 64, 3)
    with pytest.raises(OSError):
        _require_static_linux_elf(io.BytesIO(executable), len(executable))


def test_signed_policy_accepts_exactly_pinned_production_verifier(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hk-pinned-production"
    report = report_data(nonce, hotkey).hex()
    stable_id = "tdx-platform-sha256:" + "a" * 64
    claims = {
        "advisory_ids": [],
        "claims_bound_to_quote": True,
        "collateral_current": True,
        "debug_enabled": False,
        "intel_verified": True,
        "measurement": "m1",
        "platform_id": stable_id,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "report_data": report,
        "report_data_match": True,
        "stable_platform_id": stable_id,
        "tcb": 0,
        "tcb_status": "UpToDate",
        "tcb_svn": "0d010800000000000000000000000000",
        "tdx_attestation_key_id": "tdx-ak-sha256:" + "c" * 64,
        "tdx_pck_cert_id": "tdx-pck-cert-sha256:" + "b" * 64,
    }
    command = _fake_verifier(
        tmp_path,
        f"print({json.dumps(json.dumps(claims))})",
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", "/opt/cathedral/tdx-verifier")
    monkeypatch.setattr(
        "cathedral.verify._production_tdx_command",
        lambda _command: command.split(),
    )
    attested = verify(_make_evidence(nonce, hotkey), nonce, _production_policy("m1"))
    assert attested is not None
    assert attested.chip_id == stable_id


# ---------------------------------------------------------------------------
# Subprocess safety — nonzero exit
# ---------------------------------------------------------------------------


def test_verifier_nonzero_exit_rejects(tmp_path, monkeypatch):
    """A verifier that exits with a nonzero code must be rejected."""
    nonce = issue_nonce()
    hotkey = "hk-exit-1"
    body = "raise SystemExit(2)"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


# ---------------------------------------------------------------------------
# Subprocess safety — oversized output
# ---------------------------------------------------------------------------


def test_verifier_oversized_stdout_rejects(tmp_path, monkeypatch):
    """Output exceeding CATHEDRAL_TDX_VERIFY_MAX_OUTPUT must be rejected."""
    nonce = issue_nonce()
    hotkey = "hk-oversize-1"
    # Print 200 bytes of JSON-ish noise; cap at 100 bytes.
    body = 'print("x" * 200)'
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


# ---------------------------------------------------------------------------
# Subprocess safety — malformed JSON
# ---------------------------------------------------------------------------


def test_verifier_malformed_json_rejects(tmp_path, monkeypatch):
    """Non-JSON stdout must be rejected."""
    nonce = issue_nonce()
    hotkey = "hk-json-1"
    body = 'print("this is not json {")'
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_verifier_json_array_rejects(tmp_path, monkeypatch):
    """JSON array (not object) at top level must be rejected."""
    nonce = issue_nonce()
    hotkey = "hk-json-2"
    body = 'import json; print(json.dumps([{"intel_verified": True}]))'
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None


def test_verifier_empty_stdout_rejects(tmp_path, monkeypatch):
    """Empty stdout must be rejected."""
    nonce = issue_nonce()
    hotkey = "hk-json-3"
    body = "pass  # prints nothing"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path, body))
    assert verify(_make_evidence(nonce, hotkey), nonce, _policy("m1")) is None
