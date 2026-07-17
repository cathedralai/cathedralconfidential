from __future__ import annotations

import pytest

from cathedral.common import report_data
from cathedral.verify.tdx_quote import (
    QUOTE_ATTESTATION_KEY_SIZE,
    QUOTE_SIGNATURE_DATA_OFFSET,
    QUOTE_SIGNATURE_DATA_LEN_OFFSET,
    QUOTE_SIGNATURE_SIZE,
    TdxQuoteParseError,
    parse_tdx_quote,
)

from tests.tdx_quote_fixtures import synthetic_tdx_quote


def test_parse_tdx_quote_extracts_body_claims():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = synthetic_tdx_quote(report_data=rd)

    parsed = parse_tdx_quote(quote)

    assert parsed.header.version == 4
    assert parsed.header.tee_type == 0x81
    assert parsed.report_data == rd
    assert parsed.body.mr_td == b"M" * 48
    assert parsed.body.rtmrs == (b"0" * 48, b"1" * 48, b"2" * 48, b"3" * 48)
    assert parsed.tcb == int.from_bytes(bytes(range(16)), "big")
    assert parsed.measurement.startswith("tdx-measurement-sha256:")
    assert parsed.attestation_key_id.startswith("tdx-ak-sha256:")
    assert parsed.platform_id.startswith("tdx-pck-cert-sha256:")
    assert parsed.certification_data_type == 6
    assert parsed.debug_enabled is False


def test_parse_tdx_quote_extracts_debug_attribute():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = synthetic_tdx_quote(report_data=rd, td_attributes=(1).to_bytes(8, "little"))

    assert parse_tdx_quote(quote).debug_enabled is True


def test_parse_tdx_quote_rejects_truncated_quote():
    with pytest.raises(TdxQuoteParseError, match="too short"):
        parse_tdx_quote(b"\0" * 100)


def test_parse_tdx_quote_rejects_wrong_version():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = bytearray(synthetic_tdx_quote(report_data=rd))
    quote[0:2] = (5).to_bytes(2, "little")

    with pytest.raises(TdxQuoteParseError, match="version"):
        parse_tdx_quote(bytes(quote))


def test_parse_tdx_quote_rejects_wrong_tee_type():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = bytearray(synthetic_tdx_quote(report_data=rd))
    quote[4:8] = (0x0).to_bytes(4, "little")

    with pytest.raises(TdxQuoteParseError, match="tee_type"):
        parse_tdx_quote(bytes(quote))


def test_parse_tdx_quote_measurement_changes_when_mrtd_offset_changes():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote_a = synthetic_tdx_quote(report_data=rd, mr_td=b"A" * 48)
    quote_b = synthetic_tdx_quote(report_data=rd, mr_td=b"B" * 48)

    assert parse_tdx_quote(quote_a).measurement != parse_tdx_quote(quote_b).measurement


def test_parse_tdx_quote_rejects_missing_pck_certificate():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = bytearray(synthetic_tdx_quote(report_data=rd))
    cert_size_offset = (
        QUOTE_SIGNATURE_DATA_OFFSET + QUOTE_SIGNATURE_SIZE + QUOTE_ATTESTATION_KEY_SIZE + 2
    )
    cert_data_offset = cert_size_offset + 4
    cert_size = int.from_bytes(quote[cert_size_offset : cert_size_offset + 4], "little")
    quote[cert_data_offset : cert_data_offset + cert_size] = b"x" * cert_size

    with pytest.raises(TdxQuoteParseError, match="PEM certificate"):
        parse_tdx_quote(bytes(quote))


def test_parse_tdx_quote_rejects_unsupported_certification_type():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = bytearray(synthetic_tdx_quote(report_data=rd))
    cert_type_offset = QUOTE_SIGNATURE_DATA_OFFSET + QUOTE_SIGNATURE_SIZE + QUOTE_ATTESTATION_KEY_SIZE
    quote[cert_type_offset : cert_type_offset + 2] = (5).to_bytes(2, "little")

    with pytest.raises(TdxQuoteParseError, match="certification data type"):
        parse_tdx_quote(bytes(quote))


def test_parse_tdx_quote_rejects_trailing_signature_data():
    rd = report_data(b"n" * 32, "hotkey-tdx")
    quote = bytearray(synthetic_tdx_quote(report_data=rd))
    signature_data_len = int.from_bytes(
        quote[QUOTE_SIGNATURE_DATA_LEN_OFFSET:QUOTE_SIGNATURE_DATA_OFFSET], "little"
    )
    quote[QUOTE_SIGNATURE_DATA_LEN_OFFSET:QUOTE_SIGNATURE_DATA_OFFSET] = (
        signature_data_len + 1
    ).to_bytes(4, "little")
    quote.extend(b"x")

    with pytest.raises(TdxQuoteParseError, match="trailing bytes"):
        parse_tdx_quote(bytes(quote))
