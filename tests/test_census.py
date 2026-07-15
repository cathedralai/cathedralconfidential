"""Contract: the CC census probe returns a stable dict shape.

Runs anywhere — census() only reads local device nodes / nvidia-smi and never
attests, so on non-CC hosts every capability is simply False.
"""

from __future__ import annotations

import cathedral.census as census_mod
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


def test_tdx_false_on_generic_tsm_without_tdx_marker(monkeypatch):
    """configfs-tsm alone must NOT read as TDX — SEV-SNP guests expose it too."""
    present = {"/sys/kernel/config/tsm/report"}  # SNP guest: TSM present, no tdx_guest
    monkeypatch.setattr(census_mod.os.path, "exists", lambda p: p in present)
    assert census_mod._tdx() is False


def test_tdx_true_via_guest_module(monkeypatch):
    present = {"/sys/kernel/config/tsm/report", "/sys/module/tdx_guest"}
    monkeypatch.setattr(census_mod.os.path, "exists", lambda p: p in present)
    assert census_mod._tdx() is True


def test_tdx_true_via_guest_device(monkeypatch):
    monkeypatch.setattr(census_mod.os.path, "exists", lambda p: p == "/dev/tdx_guest")
    assert census_mod._tdx() is True
