"""Channel-key fingerprints used by the attestation transport.

The runtime stays dependency-free.  A small strict DER reader extracts the
SubjectPublicKeyInfo object from a peer X.509 certificate so Cathedral binds to
the public key rather than a particular certificate wrapper.
"""

from __future__ import annotations

import hashlib

from cathedral.common import ChannelBinding, ChannelBindingType


class ChannelBindingError(ValueError):
    """Raised when channel-key material is malformed or unsupported."""


def _der_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset < 0 or offset + 2 > len(data):
        raise ChannelBindingError("certificate contains truncated DER")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ChannelBindingError("certificate uses unsupported high-tag DER")
    length_octet = data[offset + 1]
    header_end = offset + 2
    if length_octet & 0x80:
        count = length_octet & 0x7F
        if count == 0 or count > 4 or header_end + count > len(data):
            raise ChannelBindingError("certificate contains invalid DER length")
        length_bytes = data[header_end : header_end + count]
        if length_bytes[0] == 0:
            raise ChannelBindingError("certificate contains non-canonical DER length")
        length = int.from_bytes(length_bytes, "big")
        if length < 128:
            raise ChannelBindingError("certificate contains non-canonical DER length")
        header_end += count
    else:
        length = length_octet
    end = header_end + length
    if end > len(data):
        raise ChannelBindingError("certificate contains truncated DER value")
    return tag, header_end, end


def extract_spki_der(certificate_der: bytes) -> bytes:
    """Return the exact DER SubjectPublicKeyInfo from one X.509 certificate."""

    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise ChannelBindingError("peer certificate is missing")
    tag, certificate_body, certificate_end = _der_tlv(certificate_der, 0)
    if tag != 0x30 or certificate_end != len(certificate_der):
        raise ChannelBindingError("peer certificate is not a canonical sequence")
    tbs_tag, tbs_body, tbs_end = _der_tlv(certificate_der, certificate_body)
    if tbs_tag != 0x30:
        raise ChannelBindingError("peer certificate has invalid TBS data")

    offset = tbs_body
    first_tag, _, first_end = _der_tlv(certificate_der, offset)
    if first_tag == 0xA0:  # optional explicit version
        offset = first_end
    # serialNumber, signature, issuer, validity, subject precede SPKI.
    for _ in range(5):
        _, _, offset = _der_tlv(certificate_der, offset)
        if offset > tbs_end:
            raise ChannelBindingError("peer certificate has invalid TBS fields")
    spki_start = offset
    spki_tag, spki_body, spki_end = _der_tlv(certificate_der, spki_start)
    if spki_tag != 0x30 or spki_end > tbs_end:
        raise ChannelBindingError("peer certificate has invalid SPKI")
    algorithm_tag, _, algorithm_end = _der_tlv(certificate_der, spki_body)
    key_tag, _, key_end = _der_tlv(certificate_der, algorithm_end)
    if algorithm_tag != 0x30 or key_tag != 0x03 or key_end != spki_end:
        raise ChannelBindingError("peer certificate has malformed SPKI")
    return certificate_der[spki_start:spki_end]


def tls_spki_binding(certificate_der: bytes) -> ChannelBinding:
    return ChannelBinding(
        ChannelBindingType.TLS_SPKI_SHA256,
        hashlib.sha256(extract_spki_der(certificate_der)).digest(),
    )


def application_key_binding(public_key: bytes) -> ChannelBinding:
    if not isinstance(public_key, bytes) or not public_key or len(public_key) > 65535:
        raise ChannelBindingError("application public key is out of bounds")
    return ChannelBinding(
        ChannelBindingType.APPLICATION_KEY_SHA256,
        hashlib.sha256(public_key).digest(),
    )
