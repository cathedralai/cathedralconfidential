from __future__ import annotations

import base64
import hashlib

from cathedral.verify.tdx_quote import QUOTE_SIGNATURE_DATA_OFFSET


def synthetic_tdx_quote(
    *,
    report_data: bytes,
    mr_td: bytes | None = None,
    tee_tcb_svn: bytes | None = None,
    attestation_key: bytes | None = None,
) -> bytes:
    assert len(report_data) == 64
    mr_td = mr_td or (b"M" * 48)
    tee_tcb_svn = tee_tcb_svn or bytes(range(16))
    attestation_key = attestation_key or hashlib.sha512(b"cathedral-ak").digest()
    assert len(mr_td) == 48
    assert len(tee_tcb_svn) == 16
    assert len(attestation_key) == 64

    header = bytearray(48)
    header[0:2] = (4).to_bytes(2, "little")
    header[2:4] = (2).to_bytes(2, "little")
    header[4:8] = (0x81).to_bytes(4, "little")
    header[8:10] = (1).to_bytes(2, "little")
    header[10:12] = (2).to_bytes(2, "little")
    header[12:28] = b"VENDOR-ID-123456"[:16]
    header[28:48] = b"cathedral-user-data!"[:20]

    body = bytearray(584)
    body[0:16] = tee_tcb_svn
    body[16:64] = b"S" * 48
    body[64:112] = b"s" * 48
    body[112:120] = b"A" * 8
    body[120:128] = b"T" * 8
    body[128:136] = b"X" * 8
    body[136:184] = mr_td
    body[184:232] = b"C" * 48
    body[232:280] = b"O" * 48
    body[280:328] = b"o" * 48
    body[328:376] = b"0" * 48
    body[376:424] = b"1" * 48
    body[424:472] = b"2" * 48
    body[472:520] = b"3" * 48
    body[520:584] = report_data

    pem_cert = (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(b"synthetic-pck-leaf-cert")
        + b"\n-----END CERTIFICATE-----\n"
    )
    cert_data = b"synthetic-cert-prefix" + pem_cert + b"synthetic-cert-suffix"

    auth = bytearray()
    auth.extend(b"Q" * 64)
    auth.extend(attestation_key)
    auth.extend((6).to_bytes(2, "little"))
    auth.extend(len(cert_data).to_bytes(4, "little"))
    auth.extend(cert_data)

    quote = bytes(header + body + len(auth).to_bytes(4, "little") + auth)
    assert len(quote) == QUOTE_SIGNATURE_DATA_OFFSET + len(auth)
    return quote
