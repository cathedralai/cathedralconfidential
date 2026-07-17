"""Strict stdlib parser for Intel TDX quote v4 policy claims.

The parser does not perform signature or collateral verification. Callers must
run DCAP / Trust Authority verification over the exact same raw quote bytes
before trusting the parsed claims.

Layout references:
- TDX quote v4 header: 48 bytes
- TD report body: 584 bytes
- A 4-byte little-endian signature-data length follows at byte 632
- Signature data begins at byte 636 with signature + attestation key

The field offsets mirror Intel's quote v4 / TD report structs. Tests pin the
offsets with mutation checks so a wrong offset changes the expected claim.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

QUOTE_HEADER_SIZE = 48
TD_REPORT_BODY_SIZE = 584
QUOTE_SIGNATURE_DATA_LEN_OFFSET = QUOTE_HEADER_SIZE + TD_REPORT_BODY_SIZE
QUOTE_SIGNATURE_DATA_OFFSET = QUOTE_SIGNATURE_DATA_LEN_OFFSET + 4
QUOTE_SIGNATURE_SIZE = 64
QUOTE_ATTESTATION_KEY_SIZE = 64
QUOTE_CERTIFICATION_HEADER_SIZE = 6

TDX_QUOTE_VERSION = 4
TDX_TEE_TYPE = 0x81
TDX_CERTIFICATION_DATA_TYPE_PCK_CHAIN = 6

_MEASUREMENT_DOMAIN = b"cathedral-tdx-measurement-v1\0"


class TdxQuoteParseError(ValueError):
    """Raised when a raw buffer is not a strict TDX quote v4 shape."""


@dataclass(frozen=True)
class TdxQuoteHeader:
    version: int
    attestation_key_type: int
    tee_type: int
    qe_svn: int
    pce_svn: int
    qe_vendor_id: bytes
    user_data: bytes


@dataclass(frozen=True)
class TdxReportBody:
    tee_tcb_svn: bytes
    mr_seam: bytes
    mr_signer_seam: bytes
    seam_attributes: bytes
    td_attributes: bytes
    xfam: bytes
    mr_td: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    rtmr0: bytes
    rtmr1: bytes
    rtmr2: bytes
    rtmr3: bytes
    report_data: bytes

    @property
    def rtmrs(self) -> tuple[bytes, bytes, bytes, bytes]:
        return (self.rtmr0, self.rtmr1, self.rtmr2, self.rtmr3)


@dataclass(frozen=True)
class ParsedTdxQuote:
    header: TdxQuoteHeader
    body: TdxReportBody
    attestation_key: bytes
    certification_data_type: int
    certification_data: bytes
    pck_leaf_cert_der: bytes

    @property
    def report_data(self) -> bytes:
        return self.body.report_data

    @property
    def measurement(self) -> str:
        """Canonical Cathedral launch measurement over TD identity fields."""

        h = hashlib.sha256()
        h.update(_MEASUREMENT_DOMAIN)
        h.update(self.body.td_attributes)
        h.update(self.body.xfam)
        h.update(self.body.mr_td)
        h.update(self.body.mr_config_id)
        h.update(self.body.mr_owner)
        h.update(self.body.mr_owner_config)
        for rtmr in self.body.rtmrs:
            h.update(rtmr)
        return "tdx-measurement-sha256:" + h.hexdigest()

    @property
    def tcb(self) -> int:
        """Deterministic integer form for the existing Policy.min_tcb contract."""

        return int.from_bytes(self.body.tee_tcb_svn, "big")

    @property
    def tcb_svn(self) -> str:
        return self.body.tee_tcb_svn.hex()

    @property
    def debug_enabled(self) -> bool:
        """Whether the TDX TD_ATTRIBUTES.DEBUG bit is set."""

        return bool(int.from_bytes(self.body.td_attributes, "little") & 0x1)

    @property
    def attestation_key_id(self) -> str:
        return "tdx-ak-sha256:" + hashlib.sha256(self.attestation_key).hexdigest()

    @property
    def platform_id(self) -> str:
        return "tdx-pck-cert-sha256:" + hashlib.sha256(self.pck_leaf_cert_der).hexdigest()


def parse_tdx_quote(raw: bytes) -> ParsedTdxQuote:
    """Parse a raw Intel TDX quote v4 after external signature verification."""

    min_len = QUOTE_SIGNATURE_DATA_OFFSET + QUOTE_SIGNATURE_SIZE + QUOTE_ATTESTATION_KEY_SIZE
    if len(raw) < min_len:
        raise TdxQuoteParseError(f"TDX quote too short: got {len(raw)} bytes, need >= {min_len}")

    header = _parse_header(raw[:QUOTE_HEADER_SIZE])
    if header.version != TDX_QUOTE_VERSION:
        raise TdxQuoteParseError(f"unsupported TDX quote version: {header.version}")
    if header.tee_type != TDX_TEE_TYPE:
        raise TdxQuoteParseError(f"unsupported TDX tee_type: 0x{header.tee_type:x}")

    body = _parse_body(raw[QUOTE_HEADER_SIZE:QUOTE_SIGNATURE_DATA_LEN_OFFSET])
    signature_data_len = int.from_bytes(
        raw[QUOTE_SIGNATURE_DATA_LEN_OFFSET:QUOTE_SIGNATURE_DATA_OFFSET], "little"
    )
    fixed_sig_len = (
        QUOTE_SIGNATURE_SIZE + QUOTE_ATTESTATION_KEY_SIZE + QUOTE_CERTIFICATION_HEADER_SIZE
    )
    if signature_data_len < fixed_sig_len:
        raise TdxQuoteParseError(f"TDX signature data too short: {signature_data_len}")
    signature_data_end = QUOTE_SIGNATURE_DATA_OFFSET + signature_data_len
    if len(raw) < signature_data_end:
        raise TdxQuoteParseError(
            f"TDX quote truncated inside signature data: got {len(raw)}, need {signature_data_end}"
        )

    signature_data = raw[QUOTE_SIGNATURE_DATA_OFFSET:signature_data_end]
    attestation_key = signature_data[
        QUOTE_SIGNATURE_SIZE : QUOTE_SIGNATURE_SIZE + QUOTE_ATTESTATION_KEY_SIZE
    ]
    if not any(attestation_key):
        raise TdxQuoteParseError("TDX quote attestation key is empty")

    cert_header_offset = QUOTE_SIGNATURE_SIZE + QUOTE_ATTESTATION_KEY_SIZE
    cert_type = int.from_bytes(signature_data[cert_header_offset : cert_header_offset + 2], "little")
    if cert_type != TDX_CERTIFICATION_DATA_TYPE_PCK_CHAIN:
        raise TdxQuoteParseError(f"unsupported TDX certification data type: {cert_type}")
    cert_size = int.from_bytes(signature_data[cert_header_offset + 2 : cert_header_offset + 6], "little")
    cert_data_offset = cert_header_offset + QUOTE_CERTIFICATION_HEADER_SIZE
    cert_data_end = cert_data_offset + cert_size
    if cert_data_end > len(signature_data):
        raise TdxQuoteParseError(
            f"TDX certification data truncated: got {len(signature_data)}, need {cert_data_end}"
        )
    if cert_data_end != len(signature_data):
        raise TdxQuoteParseError("TDX signature data has trailing bytes after certification data")
    cert_data = signature_data[cert_data_offset:cert_data_end]
    pck_leaf_cert_der = _extract_first_pem_certificate(cert_data)

    return ParsedTdxQuote(
        header=header,
        body=body,
        attestation_key=attestation_key,
        certification_data_type=cert_type,
        certification_data=cert_data,
        pck_leaf_cert_der=pck_leaf_cert_der,
    )


def _parse_header(data: bytes) -> TdxQuoteHeader:
    version, att_key_type, tee_type, qe_svn, pce_svn = struct.unpack("<HHIHH", data[:12])
    return TdxQuoteHeader(
        version=version,
        attestation_key_type=att_key_type,
        tee_type=tee_type,
        qe_svn=qe_svn,
        pce_svn=pce_svn,
        qe_vendor_id=data[12:28],
        user_data=data[28:48],
    )


def _parse_body(data: bytes) -> TdxReportBody:
    if len(data) != TD_REPORT_BODY_SIZE:
        raise TdxQuoteParseError(f"TD report body must be {TD_REPORT_BODY_SIZE} bytes")

    return TdxReportBody(
        tee_tcb_svn=data[0:16],
        mr_seam=data[16:64],
        mr_signer_seam=data[64:112],
        seam_attributes=data[112:120],
        td_attributes=data[120:128],
        xfam=data[128:136],
        mr_td=data[136:184],
        mr_config_id=data[184:232],
        mr_owner=data[232:280],
        mr_owner_config=data[280:328],
        rtmr0=data[328:376],
        rtmr1=data[376:424],
        rtmr2=data[424:472],
        rtmr3=data[472:520],
        report_data=data[520:584],
    )


def _extract_first_pem_certificate(data: bytes) -> bytes:
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    start = data.find(begin)
    if start < 0:
        raise TdxQuoteParseError("TDX certification data does not contain a PEM certificate")
    body_start = start + len(begin)
    stop = data.find(end, body_start)
    if stop < 0:
        raise TdxQuoteParseError("TDX certification data has an unterminated PEM certificate")

    b64 = b"".join(data[body_start:stop].split())
    try:
        cert_der = base64.b64decode(b64, validate=True)
    except ValueError as exc:
        raise TdxQuoteParseError("TDX PCK leaf certificate is not valid base64") from exc
    if not cert_der:
        raise TdxQuoteParseError("TDX PCK leaf certificate is empty")
    return cert_der
