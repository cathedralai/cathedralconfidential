from __future__ import annotations

from cathedral.attest import _canonicalize_tdx_configfs_quote


_SIGNED_DATA_OFFSET = 0x27C


def _quote_v4(*, signed_size: int = 4299, padding: bytes = b"") -> bytes:
    quote = bytearray(_SIGNED_DATA_OFFSET + signed_size)
    quote[:2] = (4).to_bytes(2, "little")
    quote[0x278:0x27C] = signed_size.to_bytes(4, "little")
    return bytes(quote) + padding


def test_canonicalizes_observed_configfs_zero_padding() -> None:
    canonical = _quote_v4()
    padded = canonical + bytes(3065)

    assert len(padded) == 8000
    for padding_size in (1, 3065, 4095, 4096):
        assert _canonicalize_tdx_configfs_quote(canonical + bytes(padding_size)) == canonical


def test_preserves_already_canonical_quote() -> None:
    quote = _quote_v4()

    assert _canonicalize_tdx_configfs_quote(quote) is quote


def test_preserves_nonzero_or_oversized_unsigned_suffix() -> None:
    canonical = _quote_v4()

    assert _canonicalize_tdx_configfs_quote(canonical + b"\x00\x01") == canonical + b"\x00\x01"
    assert _canonicalize_tdx_configfs_quote(canonical + bytes(4097)) == canonical + bytes(4097)


def test_preserves_non_v4_and_truncated_quotes() -> None:
    quote_v5 = bytearray(_quote_v4(padding=bytes(16)))
    quote_v5[:2] = (5).to_bytes(2, "little")
    truncated = _quote_v4()[:1000]

    assert _canonicalize_tdx_configfs_quote(bytes(quote_v5)) == bytes(quote_v5)
    assert _canonicalize_tdx_configfs_quote(truncated) == truncated
