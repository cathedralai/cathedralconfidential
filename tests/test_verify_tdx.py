"""Contract: TDX verifier adapter enforces Cathedral policy after vendor crypto.

The real DCAP / Trust Authority verifier stays outside Python. These tests use
a fake command that returns already-verified JSON claims so the hardware-free
suite can pin Cathedral's binding and policy checks.
"""

from __future__ import annotations

import sys

import pytest

from cathedral.common import Evidence, EvidenceKind, Policy, Tier, issue_nonce, report_data
from cathedral.verify import verify


def _fake_verifier(tmp_path):
    script = tmp_path / "fake_tdx_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import json
import os
import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)
print(json.dumps({
    "report_data": os.environ["FAKE_REPORT_DATA"],
    "measurement": os.environ["FAKE_MEASUREMENT"],
    "tcb": int(os.environ["FAKE_TCB"]),
    "platform_id": os.environ["FAKE_PLATFORM_ID"],
}))
""".lstrip()
    )
    return f"{sys.executable} {script}"


def test_tdx_verify_accepts_verified_claims(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    attested = verify(evidence, nonce, policy)

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_TDX
    assert attested.chip_id == "tdx-platform-1"
    assert attested.measurement == "tdx-measurement-1"
    assert attested.tcb == 7


def test_tdx_verify_rejects_wrong_report_data(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(issue_nonce(), hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_disallowed_measurement(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"other-measurement"}, min_tcb=0)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_requires_external_verifier(monkeypatch):
    nonce = issue_nonce()
    monkeypatch.delenv("CATHEDRAL_TDX_VERIFY_CMD", raising=False)
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, "hotkey-tdx")

    with pytest.raises(NotImplementedError):
        verify(evidence, nonce, Policy(allowed_measurements={"m"}))
