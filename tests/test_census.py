"""Contract: the CC census probe returns a stable dict shape.

Runs anywhere — census() only reads local device nodes / nvidia-smi and never
attests, so on non-CC hosts every capability is simply False.
"""

from __future__ import annotations

from cathedral.census import census


def test_census_returns_expected_keys():
    r = census()
    assert {"sev_snp", "tdx", "gpu_cc", "gpu_cc_detail", "cc_capable"} <= set(r)


def test_census_field_types():
    r = census()
    assert isinstance(r["sev_snp"], bool)
    assert isinstance(r["tdx"], bool)
    assert isinstance(r["gpu_cc"], bool)
    assert isinstance(r["gpu_cc_detail"], list)
    assert isinstance(r["cc_capable"], bool)


def test_cc_capable_is_or_of_capabilities():
    r = census()
    assert r["cc_capable"] == bool(r["sev_snp"] or r["tdx"] or r["gpu_cc"])
