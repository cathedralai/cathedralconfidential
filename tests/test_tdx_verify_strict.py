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

import sys
import time

from cathedral.common import Evidence, EvidenceKind, Policy, issue_nonce, report_data
from cathedral.verify import verify


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
