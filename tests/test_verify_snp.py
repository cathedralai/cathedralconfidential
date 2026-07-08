"""Contract: hardware-free AMD SEV-SNP report parsing and binding checks."""

from __future__ import annotations

from pathlib import Path

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


def test_chain_unavailable_is_not_verified():
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()

    verdict = verify_snp_report_data(
        report,
        request_data,
        _policy_for(report),
        snpguest_path="/definitely/not/snpguest",
    )

    assert verdict is not None
    assert verdict.verification_status == STRUCTURE_OK_CHAIN_UNVERIFIED
    assert verdict.verification_status != VERIFIED
    assert verdict.chain_verified is False
