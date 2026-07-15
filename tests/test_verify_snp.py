"""Contract: hardware-free AMD SEV-SNP report parsing and binding checks."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

from cathedral.common import Policy
from cathedral.verify.snp import (
    STRUCTURE_OK_CHAIN_UNVERIFIED,
    VERIFIED,
    REPORT_DATA_OFFSET,
    parse_snp_report,
    verify_snp_report_data,
)


FIXTURES = Path(__file__).parent / "fixtures" / "snp"
REPORT = FIXTURES / "attestation-report.bin"
REQUEST_DATA = FIXTURES / "request-data.bin"


def _policy_for(report: bytes) -> Policy:
    parsed = parse_snp_report(report)
    return Policy(allowed_measurements={parsed.measurement}, min_tcb=parsed.tcb.reported)


def test_parses_real_report_data_fixture_byte_for_byte():
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()

    parsed = parse_snp_report(report)

    assert len(report) == 1184
    assert len(request_data) == 64
    assert parsed.report_data == request_data
    assert parsed.version == 5
    assert parsed.measurement
    assert parsed.chip_id
    assert parsed.tcb.reported > 0


def test_rejects_tampered_report_data():
    report = bytearray(REPORT.read_bytes())
    request_data = REQUEST_DATA.read_bytes()
    report[REPORT_DATA_OFFSET] ^= 0x01

    assert verify_snp_report_data(bytes(report), request_data, _policy_for(bytes(report))) is None


def test_rejects_wrong_nonce_binding():
    report = REPORT.read_bytes()
    wrong_request_data = b"\x00" * 64

    assert verify_snp_report_data(report, wrong_request_data, _policy_for(report)) is None


def test_chain_unavailable_rejects_by_default():
    """The admission path fails closed: no vendor chain means no Attested.

    A structurally valid report with a forged signature must never become an
    admission ticket on a box that happens to lack snpguest.
    """
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()

    verdict = verify_snp_report_data(
        report,
        request_data,
        _policy_for(report),
        snpguest_path="/definitely/not/snpguest",
    )

    assert verdict is None


def test_chain_unavailable_diagnostic_status_via_opt_in():
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()

    verdict = verify_snp_report_data(
        report,
        request_data,
        _policy_for(report),
        snpguest_path="/definitely/not/snpguest",
        require_chain=False,
    )

    assert verdict is not None
    assert verdict.verification_status == STRUCTURE_OK_CHAIN_UNVERIFIED
    assert verdict.verification_status != VERIFIED
    assert verdict.chain_verified is False


def _fake_snpguest(tmp_path: Path) -> str:
    """A resolvable executable so _resolve_snpguest returns a path; the real
    binary is never invoked because subprocess.run is mocked in these tests."""
    binary = tmp_path / "snpguest"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    return str(binary)


def _ok(cmd):
    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


def test_every_snpguest_call_passes_timeout(tmp_path):
    """A hung snpguest must not wedge the validator scoring path: every
    subprocess invocation is bounded by a wall-clock timeout."""
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()
    snpguest = _fake_snpguest(tmp_path)

    with mock.patch(
        "cathedral.verify.snp.subprocess.run",
        side_effect=lambda cmd, *a, **k: _ok(cmd),
    ) as run:
        verify_snp_report_data(
            report, request_data, _policy_for(report), snpguest_path=snpguest
        )

    assert run.call_count >= 1
    for call in run.call_args_list:
        assert call.kwargs.get("timeout"), f"subprocess.run without timeout: {call.args}"


def test_ca_fetch_never_uses_hardcoded_generation(tmp_path):
    """The CA generation is always derived from the report itself. A hardcoded
    milan/genoa/turin fallback would fetch the wrong CA on non-Milan parts and
    reject legitimate hardware (mirrors the collector fix in #16)."""
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()
    snpguest = _fake_snpguest(tmp_path)

    seen: list[list[str]] = []

    def fake_run(cmd, *a, **k):
        seen.append(cmd)
        if cmd[1:3] == ["fetch", "ca"]:
            raise subprocess.CalledProcessError(1, cmd)
        return _ok(cmd)

    with mock.patch("cathedral.verify.snp.subprocess.run", side_effect=fake_run), mock.patch(
        "cathedral.verify.snp.time.sleep"
    ):
        verdict = verify_snp_report_data(
            report, request_data, _policy_for(report), snpguest_path=snpguest
        )

    ca_cmds = [c for c in seen if c[1:3] == ["fetch", "ca"]]
    assert ca_cmds, "no CA fetch was attempted"
    for c in ca_cmds:
        assert not ({"milan", "genoa", "turin"} & set(c)), f"hardcoded CA generation: {c}"
    assert verdict is None  # fail-closed when the chain cannot be built


def test_hung_snpguest_fails_closed(tmp_path):
    """A snpguest that hangs (raises TimeoutExpired) must fail closed to None,
    not propagate an unhandled exception into the caller's scoring loop."""
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()
    snpguest = _fake_snpguest(tmp_path)

    with mock.patch(
        "cathedral.verify.snp.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="snpguest", timeout=30),
    ), mock.patch("cathedral.verify.snp.time.sleep"):
        verdict = verify_snp_report_data(
            report, request_data, _policy_for(report), snpguest_path=snpguest
        )

    assert verdict is None
