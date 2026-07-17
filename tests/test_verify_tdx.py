"""Contract: TDX verifier adapter enforces Cathedral policy after vendor crypto.

The real DCAP / Trust Authority verifier stays outside Python. These tests use
a fake command that returns already-verified JSON claims so the hardware-free
suite can pin Cathedral's binding and policy checks.
"""

from __future__ import annotations

import sys
import json
import os

import pytest

from cathedral.common import (
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    Policy,
    Tier,
    issue_nonce,
    report_data,
    report_data_v2,
)
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
    **({"tcb_svn": os.environ["FAKE_TCB_SVN"]} if "FAKE_TCB_SVN" in os.environ else {}),
    **({"tcb_status": os.environ["FAKE_TCB_STATUS"]} if "FAKE_TCB_STATUS" in os.environ else {}),
    **({"platform_id": os.environ["FAKE_PLATFORM_ID"]} if "FAKE_PLATFORM_ID" in os.environ else {}),
    "intel_verified": os.environ.get("FAKE_INTEL_VERIFIED", "true").lower() == "true",
    "report_data_match": os.environ.get("FAKE_REPORT_DATA_MATCH", "true").lower() == "true",
    **json.loads(os.environ.get("FAKE_EXTRA_CLAIMS", "{}")),
}))
""".lstrip()
    )
    return f"{sys.executable} {script}"


def _configure_strict_verifier(
    tmp_path,
    monkeypatch,
    *,
    nonce: bytes,
    hotkey: str,
    claims: dict | None = None,
) -> tuple[Evidence, str]:
    stable_id = "tdx-platform-sha256:" + "a" * 64
    strict_claims = {
        "tcb_svn": "0d010800000000000000000000000000",
        "tcb_status": "UpToDate",
        "advisory_ids": [],
        "debug_enabled": False,
        "collateral_current": True,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
        "stable_platform_id": stable_id,
        "platform_id": stable_id,
        "tdx_pck_cert_id": "tdx-pck-cert-sha256:" + "b" * 64,
        "tdx_attestation_key_id": "tdx-ak-sha256:" + "c" * 64,
    }
    if claims:
        strict_claims.update(claims)
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_EXTRA_CLAIMS", json.dumps(strict_claims))
    return Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey), stable_id


def _strict_policy(
    *, status: str = "UpToDate", advisories: set[str] | None = None, min_tcb: int = 0
) -> Policy:
    return Policy(
        allowed_measurements={"tdx-measurement-1"},
        min_tcb=min_tcb,
        tdx_strict=True,
        tdx_allowed_tcb_statuses={status},
        tdx_allowed_advisories=advisories or set(),
    )


def test_tdx_verify_accepts_verified_claims(tmp_path, monkeypatch, caplog):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    with caplog.at_level("WARNING", logger="cathedral.verify"):
        attested = verify(evidence, nonce, policy)

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_TDX
    assert attested.chip_id == "tdx-platform-1"
    assert attested.measurement == "tdx-measurement-1"
    assert attested.tcb == 7
    assert attested.policy_mode == "compatibility"
    assert "compatibility policy mode" in caplog.text


def test_tdx_verify_accepts_report_data_v2_and_rejects_changed_binding(
    tmp_path, monkeypatch
):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32)
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv(
        "FAKE_REPORT_DATA", report_data_v2(nonce, hotkey, binding).hex()
    )
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)
    evidence = Evidence(
        EvidenceKind.TDX,
        b"tdx-quote",
        nonce,
        hotkey,
        report_data_version=2,
        channel_binding=binding,
    )

    assert verify(evidence, nonce, policy) is not None
    changed = Evidence(
        EvidenceKind.TDX,
        b"tdx-quote",
        nonce,
        hotkey,
        report_data_version=2,
        channel_binding=ChannelBinding(
            ChannelBindingType.TLS_SPKI_SHA256, b"b" * 32
        ),
    )
    assert verify(changed, nonce, policy) is None


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


def test_tdx_verify_rejects_positive_tcb_floor_for_raw_tcb_svn(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "999")
    monkeypatch.setenv("FAKE_TCB_SVN", "0d010800000000000000000000000000")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=1)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_explicit_failed_intel_verdict(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")
    monkeypatch.setenv("FAKE_INTEL_VERIFIED", "false")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_explicit_report_data_mismatch(tmp_path, monkeypatch):
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _fake_verifier(tmp_path))
    monkeypatch.setenv("FAKE_REPORT_DATA", report_data(nonce, hotkey).hex())
    monkeypatch.setenv("FAKE_MEASUREMENT", "tdx-measurement-1")
    monkeypatch.setenv("FAKE_TCB", "7")
    monkeypatch.setenv("FAKE_PLATFORM_ID", "tdx-platform-1")
    monkeypatch.setenv("FAKE_REPORT_DATA_MATCH", "false")

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    assert verify(evidence, nonce, policy) is None


def test_tdx_strict_accepts_complete_typed_claims(tmp_path, monkeypatch):
    nonce = issue_nonce()
    evidence, stable_id = _configure_strict_verifier(
        tmp_path, monkeypatch, nonce=nonce, hotkey="hotkey-tdx"
    )

    attested = verify(evidence, nonce, _strict_policy(min_tcb=2**256 - 1))

    assert attested is not None
    assert attested.chip_id == stable_id
    assert attested.policy_mode == "strict"
    assert attested.tcb_status == "UpToDate"
    assert attested.advisory_ids == ()
    assert attested.debug_enabled is False
    assert attested.collateral_current is True
    assert attested.platform_identity_kind == "stable"
    assert attested.tcb_svn == "0d010800000000000000000000000000"
    assert attested.tcb == int(attested.tcb_svn, 16)
    assert attested.pck_cert_id == "tdx-pck-cert-sha256:" + "b" * 64
    assert attested.attestation_key_id == "tdx-ak-sha256:" + "c" * 64


@pytest.mark.parametrize(
    "status",
    [
        "OutOfDate",
        "ConfigurationNeeded",
        "OutOfDateConfigurationNeeded",
        "SWHardeningNeeded",
        "ConfigurationAndSWHardeningNeeded",
    ],
)
def test_tdx_strict_accepts_named_exception_for_recognized_noncurrent_status(
    tmp_path, monkeypatch, status
):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path,
        monkeypatch,
        nonce=nonce,
        hotkey="hotkey-tdx",
        claims={"tcb_status": status, "advisory_ids": ["INTEL-SA-01234"]},
    )

    attested = verify(
        evidence,
        nonce,
        _strict_policy(status=status, advisories={"INTEL-SA-01234"}),
    )

    assert attested is not None
    assert attested.tcb_status == status
    assert attested.advisory_ids == ("INTEL-SA-01234",)


@pytest.mark.parametrize(
    ("status", "advisories"),
    [
        ("Revoked", []),
        ("FutureStatus", []),
        ("OutOfDate", []),
        ("OutOfDate", ["INTEL-SA-99999"]),
    ],
)
def test_tdx_strict_rejects_unsafe_or_unapproved_status(
    tmp_path, monkeypatch, status, advisories
):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path,
        monkeypatch,
        nonce=nonce,
        hotkey="hotkey-tdx",
        claims={"tcb_status": status, "advisory_ids": advisories},
    )
    policy = _strict_policy()

    assert verify(evidence, nonce, policy) is None


def test_tdx_policy_cannot_allowlist_revoked_or_unknown_status():
    with pytest.raises(ValueError, match="Revoked"):
        _strict_policy(status="Revoked")
    with pytest.raises(ValueError, match="unknown"):
        _strict_policy(status="FutureStatus")


@pytest.mark.parametrize(
    "missing_claim",
    [
        "tcb_svn",
        "tcb_status",
        "advisory_ids",
        "debug_enabled",
        "collateral_current",
        "platform_identity_kind",
        "platform_identity_verified",
        "claims_bound_to_quote",
        "stable_platform_id",
        "platform_id",
        "tdx_pck_cert_id",
        "tdx_attestation_key_id",
    ],
)
def test_tdx_strict_rejects_missing_typed_claim(tmp_path, monkeypatch, missing_claim):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path, monkeypatch, nonce=nonce, hotkey="hotkey-tdx"
    )
    claims = json.loads(os.environ["FAKE_EXTRA_CLAIMS"])
    del claims[missing_claim]
    monkeypatch.setenv("FAKE_EXTRA_CLAIMS", json.dumps(claims))

    assert verify(evidence, nonce, _strict_policy()) is None


def test_tdx_strict_noncurrent_status_requires_named_advisory(tmp_path, monkeypatch):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path,
        monkeypatch,
        nonce=nonce,
        hotkey="hotkey-tdx",
        claims={"tcb_status": "OutOfDate", "advisory_ids": []},
    )

    assert verify(evidence, nonce, _strict_policy(status="OutOfDate")) is None


@pytest.mark.parametrize(
    ("claim", "bad_value"),
    [
        ("tcb_svn", "xyz"),
        ("tcb_status", 1),
        ("advisory_ids", "INTEL-SA-01234"),
        ("advisory_ids", ["INTEL-SA-01234", "INTEL-SA-01234"]),
        ("advisory_ids", [""]),
        ("debug_enabled", "false"),
        ("debug_enabled", True),
        ("collateral_current", "true"),
        ("collateral_current", False),
        ("platform_identity_verified", 1),
        ("claims_bound_to_quote", False),
        ("stable_platform_id", "raw-sensitive-id"),
        ("tdx_pck_cert_id", "not-a-digest"),
        ("tdx_attestation_key_id", "not-a-digest"),
    ],
)
def test_tdx_strict_rejects_malformed_or_unsafe_typed_claim(
    tmp_path, monkeypatch, claim, bad_value
):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path,
        monkeypatch,
        nonce=nonce,
        hotkey="hotkey-tdx",
        claims={claim: bad_value},
    )

    assert verify(evidence, nonce, _strict_policy()) is None


def test_tdx_strict_rejects_contradictory_platform_identity(tmp_path, monkeypatch):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path,
        monkeypatch,
        nonce=nonce,
        hotkey="hotkey-tdx",
        claims={"platform_id": "tdx-platform-sha256:" + "d" * 64},
    )

    assert verify(evidence, nonce, _strict_policy()) is None


def test_tdx_strict_rejects_undocumented_status_alias(tmp_path, monkeypatch):
    nonce = issue_nonce()
    evidence, _ = _configure_strict_verifier(
        tmp_path, monkeypatch, nonce=nonce, hotkey="hotkey-tdx"
    )
    claims = json.loads(os.environ["FAKE_EXTRA_CLAIMS"])
    del claims["tcb_status"]
    claims["tdx_tcb_status"] = "UpToDate"
    monkeypatch.setenv("FAKE_EXTRA_CLAIMS", json.dumps(claims))

    assert verify(evidence, nonce, _strict_policy()) is None


@pytest.mark.parametrize(
    ("claim", "bad_value"),
    [
        ("stable_platform_id", "tdx-platform-sha256:" + "a" * 62 + "  "),
        ("tdx_pck_cert_id", "tdx-pck-cert-sha256:" + "b" * 62 + "  "),
        ("tcb_svn", "0d0108000000000000000000000000  "),
    ],
)
def test_tdx_strict_rejects_hex_with_whitespace(
    tmp_path, monkeypatch, claim, bad_value
):
    nonce = issue_nonce()
    claims = {claim: bad_value}
    if claim == "stable_platform_id":
        claims["platform_id"] = bad_value
    evidence, _ = _configure_strict_verifier(
        tmp_path,
        monkeypatch,
        nonce=nonce,
        hotkey="hotkey-tdx",
        claims=claims,
    )

    assert verify(evidence, nonce, _strict_policy()) is None


def test_tdx_strict_platform_identity_survives_pck_rotation(tmp_path, monkeypatch):
    nonce = issue_nonce()
    evidence, stable_id = _configure_strict_verifier(
        tmp_path, monkeypatch, nonce=nonce, hotkey="hotkey-tdx"
    )
    first = verify(evidence, nonce, _strict_policy())
    claims = json.loads(os.environ["FAKE_EXTRA_CLAIMS"])
    claims["tdx_pck_cert_id"] = "tdx-pck-cert-sha256:" + "d" * 64
    claims["tdx_attestation_key_id"] = "tdx-ak-sha256:" + "e" * 64
    monkeypatch.setenv("FAKE_EXTRA_CLAIMS", json.dumps(claims))
    second = verify(evidence, nonce, _strict_policy())

    assert first is not None and second is not None
    assert first.chip_id == second.chip_id == stable_id
    assert first.pck_cert_id != second.pck_cert_id
    assert first.attestation_key_id != second.attestation_key_id


def test_tdx_strict_distinct_platforms_do_not_deduplicate(tmp_path, monkeypatch):
    nonce = issue_nonce()
    evidence, first_id = _configure_strict_verifier(
        tmp_path, monkeypatch, nonce=nonce, hotkey="hotkey-tdx"
    )
    first = verify(evidence, nonce, _strict_policy())
    second_id = "tdx-platform-sha256:" + "f" * 64
    claims = json.loads(os.environ["FAKE_EXTRA_CLAIMS"])
    claims["stable_platform_id"] = second_id
    claims["platform_id"] = second_id
    monkeypatch.setenv("FAKE_EXTRA_CLAIMS", json.dumps(claims))
    second = verify(evidence, nonce, _strict_policy())

    assert first is not None and second is not None
    assert first.chip_id == first_id
    assert second.chip_id == second_id
    assert first.chip_id != second.chip_id


def test_tdx_verify_requires_external_verifier(monkeypatch):
    nonce = issue_nonce()
    monkeypatch.delenv("CATHEDRAL_TDX_VERIFY_CMD", raising=False)
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, "hotkey-tdx")

    with pytest.raises(NotImplementedError):
        verify(evidence, nonce, Policy(allowed_measurements={"m"}))


def test_tdx_verify_rejects_unbounded_stdout_output(tmp_path, monkeypatch):
    """Verify that a child writing excessive stdout is killed and rejected."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "spam_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Write 512 KB to stdout (exceeds typical 1 MB cap when combined with stderr)
for _ in range(64):
    print("x" * 8192)
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "102400")  # 100 KB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    # Should be rejected due to excessive output
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_unbounded_stderr_output(tmp_path, monkeypatch):
    """Verify that a child writing excessive stderr is killed and rejected."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "spam_stderr_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Write 512 KB to stderr
for _ in range(64):
    print("y" * 8192, file=sys.stderr)
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "102400")  # 100 KB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    # Should be rejected due to excessive stderr
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_unbounded_concurrent_output(tmp_path, monkeypatch):
    """Verify that concurrent stdout+stderr writes are capped together."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "concurrent_spam_verifier.py"
    script.write_text(
        """
from __future__ import annotations

import sys
import threading

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Write 300 KB to stdout and 300 KB to stderr concurrently
def spam_stdout():
    for _ in range(38):
        print("a" * 8192)

def spam_stderr():
    for _ in range(38):
        print("b" * 8192, file=sys.stderr)

t1 = threading.Thread(target=spam_stdout)
t2 = threading.Thread(target=spam_stderr)
t1.start()
t2.start()
t1.join()
t2.join()
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "102400")  # 100 KB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0)

    # Should be rejected; combined output exceeds cap
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_accepts_output_within_cap(tmp_path, monkeypatch):
    """Verify that output within the cap is accepted and parsed normally."""
    nonce = issue_nonce()
    hotkey = "hotkey-tdx"
    script = tmp_path / "ok_verifier.py"
    script.write_text(
        f"""
from __future__ import annotations

import json
import os
import sys

quote = open(sys.argv[-1], "rb").read()
if quote != b"tdx-quote":
    raise SystemExit(2)

# Output a valid JSON response plus a small warning on stderr
print(json.dumps({{
    "report_data": "{report_data(nonce, hotkey).hex()}",
    "measurement": "tdx-measurement-1",
    "tcb": 7,
    "platform_id": "tdx-platform-1",
    "intel_verified": True,
    "report_data_match": True,
}}))

print("Warning: this is a test", file=sys.stderr)
""".lstrip()
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "1048576")  # 1 MB cap

    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7)

    attested = verify(evidence, nonce, policy)

    assert attested is not None
    assert attested.tier is Tier.CC_CPU_TDX
    assert attested.chip_id == "tdx-platform-1"
    assert attested.measurement == "tdx-measurement-1"
    assert attested.tcb == 7


# ---------------------------------------------------------------------------
# Regression tests for the race-free bounded reader
# ---------------------------------------------------------------------------


def test_tdx_verify_rejects_fast_exit_overflow(tmp_path, monkeypatch):
    """Child writes 500 bytes then exits immediately; cap=100 must reject it.

    Regression: old drain path read remaining stdout/stderr after proc.wait()
    without updating combined_bytes, letting a fast-exit child bypass the cap.
    """
    script = tmp_path / "fast_exit.py"
    script.write_text(
        """\
import sys
open(sys.argv[-1], "rb").read()  # consume quote arg
sys.stdout.buffer.write(b"x" * 500)
sys.stdout.buffer.flush()
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")

    nonce = issue_nonce()
    hotkey = "hotkey-overflow"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_rejects_101_bytes_accepts_100(tmp_path, monkeypatch):
    """Exact boundary: 101 bytes rejected, exactly 100 bytes accepted.

    Regression: old hard_limit = max_output + 1024 accepted output between
    max_output and max_output+1024, breaking the stated byte cap.
    """
    import shlex
    import os
    import tempfile
    from cathedral.verify import _read_bounded_subprocess

    def _make_script(n_bytes: int) -> str:
        s = tmp_path / f"boundary_{n_bytes}.py"
        s.write_text(
            f"""\
import sys
open(sys.argv[-1], "rb").read()
sys.stdout.buffer.write(b"z" * {n_bytes})
sys.stdout.buffer.flush()
"""
        )
        return f"{sys.executable} {s}"

    nonce = issue_nonce()
    hotkey = "hotkey-boundary"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)

    # 101 bytes against a 100-byte cap must be rejected via verify()
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", _make_script(101))
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")
    assert verify(evidence, nonce, policy) is None

    # Exactly 100 bytes must not be rejected by the cap.
    with tempfile.TemporaryDirectory() as td:
        quote_path = os.path.join(td, "quote.bin")
        with open(quote_path, "wb") as f:
            f.write(b"tdx-quote")
        stdout, stderr, rc = _read_bounded_subprocess(
            shlex.split(_make_script(100)) + [quote_path], 100, 10
        )
    assert rc == 0
    assert len(stdout.encode()) == 100


def test_tdx_verify_combined_stdout_stderr_cap(tmp_path, monkeypatch):
    """50 bytes stdout + 51 bytes stderr = 101 combined; cap=100 must reject.

    Regression: combined counter must track both streams together, not each
    stream independently.
    """
    script = tmp_path / "split_output.py"
    script.write_text(
        """\
import sys
open(sys.argv[-1], "rb").read()
sys.stdout.buffer.write(b"a" * 50)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b"b" * 51)
sys.stderr.buffer.flush()
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "100")

    nonce = issue_nonce()
    hotkey = "hotkey-combined"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)
    assert verify(evidence, nonce, policy) is None


def test_tdx_verify_timeout_kills_child(tmp_path, monkeypatch):
    """Child that sleeps forever is killed promptly on timeout; no zombie.

    Regression: daemon thread + 1 s join could leave the child running if
    proc.wait() raised TimeoutExpired before the reader thread noticed.
    """
    import time

    script = tmp_path / "sleep_forever.py"
    script.write_text(
        """\
import time, sys
open(sys.argv[-1], "rb").read()
time.sleep(3600)
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_TIMEOUT", "1")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "1048576")

    nonce = issue_nonce()
    hotkey = "hotkey-timeout"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)

    t0 = time.monotonic()
    result = verify(evidence, nonce, policy)
    elapsed = time.monotonic() - t0

    assert result is None  # timeout causes rejection
    assert elapsed < 5, f"timeout took {elapsed:.1f}s, expected <5"


def test_tdx_verify_timeout_after_pipes_closed(tmp_path, monkeypatch):
    """Child closes pipes then sleeps; deadline not extended after EOF.

    Regression: wait_secs = max(deadline - time.monotonic(), 1.0) could
    extend the configured timeout by up to 1 second. If both pipes reach EOF
    with 0.1s remaining on a 1s timeout, the child still runs for up to 1.1s.
    """
    import time

    script = tmp_path / "close_and_sleep.py"
    script.write_text(
        """\
import os, sys, time
open(sys.argv[-1], "rb").read()
os.close(1)  # close stdout
os.close(2)  # close stderr
time.sleep(3600)  # child keeps running after pipes closed
"""
    )
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", f"{sys.executable} {script}")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_TIMEOUT", "1")
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_MAX_OUTPUT", "1048576")

    nonce = issue_nonce()
    hotkey = "hotkey-pipe-close"
    evidence = Evidence(EvidenceKind.TDX, b"tdx-quote", nonce, hotkey)
    policy = Policy(allowed_measurements=set(), min_tcb=0)

    t0 = time.monotonic()
    result = verify(evidence, nonce, policy)
    elapsed = time.monotonic() - t0

    assert result is None  # timeout causes rejection
    # Must fire within ~1.2s (1s timeout + small overhead), not ~2s
    assert elapsed < 2, f"timeout took {elapsed:.1f}s, expected <2s (suggests 1s timeout extended)"
