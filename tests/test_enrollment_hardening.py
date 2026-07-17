"""Tests for the CONFIDENTIAL ENROLLMENT AND PROBING hardening lane (TDX-CPU).

Adapted from codex/enrollment-hardening. All evidence is TDX; verifier is
monkeypatched to return Attested(CC_CPU_TDX). No SNP fixtures, no
cathedral.verify.snp dependency.

Covers:
  1. Changed endpoint clears VERIFIED state (PENDING).
  2. Same endpoint re-enroll preserves attestation state.
  3. Registration gate (production mode, providers).
  4. X-Forwarded-For / trusted proxy / per-hotkey durable bounds.
  5. Hostname resolution gates network access; DNS-pinned connector.
  6. Bounded concurrent probes isolate failures.
  7. Expired chip binding allows rotation; unexpired blocks.
  8. JsonHotkeyRegistrationProvider unit cases.
  9. Production mode with file provider.
 10. Pre-resolved connector stores original hostname / uses validated IP.
 11. max_workers < 1 raises ValueError.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sqlite3
import socket as _socket_module
import threading
import time
from base64 import b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from cathedral.assurance import attestation_claims
from substrateinterface import Keypair, KeypairType

from cathedral.common import Attested, EvidenceKind, Policy, Tier
from cathedral.enroll import (
    IpRateLimiter,
    JsonHotkeyRegistrationProvider,
    RegistryApp,
    RegistryStore,
    canonical_enroll_payload,
    now_iso,
)
from cathedral.prober import (
    _PreResolvedHTTPConnection,
    _PreResolvedHTTPSConnection,
    _request_evidence,
    _resolve_endpoint,
    probe_once,
)


def _attested(chip_id: str, measurement: str = "measurement") -> Attested:
    policy = Policy(allowed_measurements={measurement})
    return Attested(
        Tier.CC_CPU_TDX,
        chip_id,
        measurement,
        1,
        assurance=attestation_claims(chip_id.encode(), policy),
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

KEYPAIR = Keypair.create_from_uri("//Alice", crypto_type=KeypairType.SR25519)
HOTKEY = KEYPAIR.ss58_address

TDX_QUOTE = b"\x04\x00" + b"\xbb" * 254
TDX_CHIP_ID = "tdx-enrollment-" + "ab" * 16
TDX_MEASUREMENT = "tdx-enrollment-meas-" + "cd" * 16


def _signed_payload(
    endpoint_url: str = "https://miner.example.com:8090",
    *,
    keypair: Keypair = KEYPAIR,
    hotkey: str = HOTKEY,
    nonce: str = "aa" * 16,
    timestamp: str | None = None,
) -> dict[str, str]:
    ts = timestamp if timestamp is not None else now_iso()
    message = canonical_enroll_payload(hotkey, endpoint_url, nonce, ts)
    sig = b64encode(keypair.sign(message)).decode("ascii")
    return {
        "hotkey": hotkey,
        "endpoint_url": endpoint_url,
        "nonce": nonce,
        "timestamp": ts,
        "signature_b64": sig,
    }


def _call(
    app: RegistryApp,
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    remote_addr: str = "1.2.3.4",
    forwarded_for: str | None = None,
) -> tuple[int, dict]:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "REMOTE_ADDR": remote_addr,
    }
    if forwarded_for is not None:
        environ["HTTP_X_FORWARDED_FOR"] = forwarded_for
    seen: dict = {}

    def start_response(status: str, headers: list) -> None:
        seen["status"] = status

    raw = b"".join(app(environ, start_response))
    return int(seen["status"].split()[0]), json.loads(raw.decode("utf-8"))


# TDX evidence HTTP stub

def _evidence_item(kind: str, quote: bytes, payload: dict) -> dict:
    return {
        "kind": kind,
        "quote_b64": base64.b64encode(quote).decode("ascii"),
        "nonce_hex": payload["nonce_hex"],
        "miner_hotkey": payload["hotkey"],
        "cert_chain_b64": [],
    }


class _TdxHandler(BaseHTTPRequestHandler):
    """Serves a single TDX evidence item."""

    hotkey = "5" + "Z" * 47

    def do_POST(self):  # noqa: N802
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        body = json.dumps(
            _evidence_item("tdx", TDX_QUOTE, payload)
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def _serve(handler_cls: type) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _fake_tdx_verify(evidence, nonce, policy):
    """Monkeypatched verifier returning Attested(CC_CPU_TDX) for TDX evidence."""
    if evidence.kind is EvidenceKind.TDX:
        return Attested(
            tier=Tier.CC_CPU_TDX,
            chip_id=TDX_CHIP_ID,
            measurement=TDX_MEASUREMENT,
            tcb=3,
            assurance=attestation_claims(evidence.quote, policy),
        )
    return None


# ---------------------------------------------------------------------------
# Test 1: Changed endpoint clears VERIFIED state immediately
# ---------------------------------------------------------------------------

def test_endpoint_change_clears_attestation(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"), verification_ttl_seconds=3600)
    hotkey = "5" + "A" * 47
    chip_id = "ab" * 32

    store.enroll(hotkey, "https://old.example.com")
    store.record_verdict(hotkey, _attested(chip_id))

    board = store.board()
    assert board["miners"][0]["verification_status"] == "VERIFIED"
    assert board["count"] == 1

    store.enroll(hotkey, "https://new.example.com")

    board = store.board()
    assert board["miners"][0]["verification_status"] == "PENDING"
    assert board["miners"][0]["chip_id_prefix"] is None
    assert board["count"] == 0


def test_public_board_exposes_claim_statuses_without_audit_digests(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "P" * 47
    store.enroll(hotkey, "http://127.0.0.1:9001")
    policy = Policy(allowed_measurements={"measurement"})
    claims = attestation_claims(b"quote", policy)
    store.record_verdict(
        hotkey,
        Attested(
            Tier.CC_CPU_TDX,
            "chip",
            "measurement",
            1,
            assurance=claims,
        ),
    )

    public = store.board()["miners"][0]["assurance"]

    assert public["claims"]["hardware"]["status"] == "passed"
    assert public["claims"]["channel"]["status"] == "not_evaluated"
    assert "evidence_digest" not in str(public)
    assert "policy_digest" not in str(public)


def test_registry_rejects_legacy_verified_flag_without_typed_claims(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey = "5" + "L" * 47
    store.enroll(hotkey, "http://127.0.0.1:9001")

    store.record_verdict(
        hotkey, Attested(Tier.CC_CPU_TDX, "chip", "measurement", 1, "VERIFIED")
    )

    miner = store.board()["miners"][0]
    assert miner["verification_status"] == "FAILED"
    assert miner["chip_id_prefix"] is None
    assert miner["tier"] is None
    assert miner["assurance"]["claims"]["hardware"]["status"] == "not_evaluated"


def test_registry_migrates_legacy_schema_and_demotes_persisted_verified_row(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-registry.sqlite"
    hotkey = "5" + "M" * 47
    now = now_iso()
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE enrollments (
                hotkey TEXT PRIMARY KEY,
                endpoint_url TEXT NOT NULL,
                enrolled_at_iso TEXT NOT NULL,
                updated_at_iso TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE attestations (
                hotkey TEXT PRIMARY KEY,
                chip_id TEXT,
                tier TEXT,
                verification_status TEXT NOT NULL,
                last_verified_iso TEXT NOT NULL,
                error TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO enrollments VALUES (?, ?, ?, ?)",
            (hotkey, "http://127.0.0.1:9001", now, now),
        )
        conn.execute(
            "INSERT INTO attestations VALUES (?, ?, ?, ?, ?, ?)",
            (hotkey, "legacy-chip", "cc_cpu_tdx", "VERIFIED", now, None),
        )

    store = RegistryStore(str(path))
    with sqlite3.connect(path) as conn:
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(attestations)")
        }
    miner = store.board()["miners"][0]

    assert "assurance_json" in columns
    assert miner["verification_status"] == "FAILED"
    assert miner["chip_id_prefix"] is None
    assert miner["tier"] is None


def test_registry_chip_rotation_conflict_does_not_publish_rejected_identity(
    tmp_path: Path,
) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    owner = "5" + "O" * 47
    claimant = "5" + "C" * 47
    for hotkey in (owner, claimant):
        store.enroll(hotkey, f"http://127.0.0.1:{9001 if hotkey == owner else 9002}")

    store.record_verdict(owner, _attested("shared-chip"))
    store.record_verdict(claimant, _attested("shared-chip"))
    miners = {miner["hotkey"]: miner for miner in store.board()["miners"]}

    assert miners[owner]["verification_status"] == "VERIFIED"
    assert miners[claimant]["verification_status"] == "FAILED"
    assert miners[claimant]["chip_id_prefix"] is None
    assert miners[claimant]["tier"] is None


# ---------------------------------------------------------------------------
# Test 2: Same endpoint re-enroll preserves attestation state
# ---------------------------------------------------------------------------

def test_same_endpoint_reenroll_preserves_state(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"), verification_ttl_seconds=3600)
    hotkey = "5" + "B" * 47
    chip_id = "cd" * 32

    store.enroll(hotkey, "https://miner.example.com")
    store.record_verdict(hotkey, _attested(chip_id))

    board = store.board()
    assert board["miners"][0]["verification_status"] == "VERIFIED"
    assert board["count"] == 1

    store.enroll(hotkey, "https://miner.example.com")

    board = store.board()
    assert board["miners"][0]["verification_status"] == "VERIFIED"
    assert board["count"] == 1


# ---------------------------------------------------------------------------
# Test 3: Registration gate
# ---------------------------------------------------------------------------

class _AlwaysRegistered:
    def is_registered(self, hotkey: str) -> bool | None:
        return True


class _AlwaysUnregistered:
    def is_registered(self, hotkey: str) -> bool | None:
        return False


class _RegistrationUnavailable:
    def is_registered(self, hotkey: str) -> bool | None:
        return None


class _RegistrationRaises:
    def is_registered(self, hotkey: str) -> bool | None:
        raise RuntimeError("chain unreachable")


def test_registration_gate(tmp_path: Path) -> None:
    base = str(tmp_path)

    # production_mode=True, no provider -> fail closed
    app = RegistryApp(RegistryStore(f"{base}/r1.sqlite"), production_mode=True)
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="00" * 16, endpoint_url="https://8.8.8.8:8090"))
    assert status == 403
    assert "provider not configured" in body["error"]

    # Unregistered hotkey -> reject
    app = RegistryApp(
        RegistryStore(f"{base}/r2.sqlite"),
        registration_provider=_AlwaysUnregistered(),
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="11" * 16))
    assert status == 403
    assert "not registered" in body["error"]

    # Provider returns None (unavailable) -> fail closed
    app = RegistryApp(
        RegistryStore(f"{base}/r3.sqlite"),
        registration_provider=_RegistrationUnavailable(),
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="22" * 16))
    assert status == 403

    # Provider raises -> fail closed
    app = RegistryApp(
        RegistryStore(f"{base}/r4.sqlite"),
        registration_provider=_RegistrationRaises(),
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="33" * 16))
    assert status == 403

    # Registered -> success
    app = RegistryApp(
        RegistryStore(f"{base}/r5.sqlite"),
        registration_provider=_AlwaysRegistered(),
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="44" * 16))
    assert status == 200
    assert body == {"status": "enrolled"}

    # production_mode=False (default) with no provider -> allow (backward compat)
    app = RegistryApp(RegistryStore(f"{base}/r6.sqlite"))
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="55" * 16))
    assert status == 200


# ---------------------------------------------------------------------------
# Test 4: Forwarded address / per-hotkey durable bounds
# ---------------------------------------------------------------------------

def test_rate_limiting_trusted_proxy_and_hotkey_bounds(tmp_path: Path) -> None:
    base = str(tmp_path)

    # --- untrusted proxy: REMOTE_ADDR governs ---
    app = RegistryApp(
        RegistryStore(f"{base}/ip.sqlite"),
        IpRateLimiter(limit=1, window_seconds=60),
        hotkey_enroll_limit=100,
    )
    s, _ = _call(
        app, "POST", "/v1/enroll", _signed_payload(nonce="a0" * 16),
        remote_addr="1.2.3.4", forwarded_for="9.9.9.9",
    )
    assert s == 200

    s, body = _call(
        app, "POST", "/v1/enroll", _signed_payload(nonce="a1" * 16),
        remote_addr="1.2.3.4", forwarded_for="8.8.8.8",
    )
    assert s == 429
    assert body["error"] == "rate limit exceeded"

    s, _ = _call(
        app, "POST", "/v1/enroll", _signed_payload(nonce="a2" * 16),
        remote_addr="2.3.4.5", forwarded_for="9.9.9.9",
    )
    assert s == 200

    # --- trusted proxy ---
    app_tp = RegistryApp(
        RegistryStore(f"{base}/tp.sqlite"),
        IpRateLimiter(limit=1, window_seconds=60),
        trusted_proxy=True,
        hotkey_enroll_limit=100,
    )
    s, _ = _call(
        app_tp, "POST", "/v1/enroll", _signed_payload(nonce="b0" * 16),
        remote_addr="10.0.0.1", forwarded_for="9.9.9.9",
    )
    assert s == 200

    s, body = _call(
        app_tp, "POST", "/v1/enroll", _signed_payload(nonce="b1" * 16),
        remote_addr="10.0.0.1", forwarded_for="9.9.9.9",
    )
    assert s == 429

    s, _ = _call(
        app_tp, "POST", "/v1/enroll", _signed_payload(nonce="b2" * 16),
        remote_addr="10.0.0.1", forwarded_for="8.8.8.8",
    )
    assert s == 200

    # --- per-hotkey durable bound across app instances ---
    db_hk = f"{base}/hotkey.sqlite"
    app1 = RegistryApp(
        RegistryStore(db_hk),
        hotkey_enroll_limit=2,
        hotkey_enroll_window_seconds=3600,
    )
    s, _ = _call(app1, "POST", "/v1/enroll", _signed_payload(nonce="c0" * 16))
    assert s == 200
    s, _ = _call(app1, "POST", "/v1/enroll", _signed_payload(nonce="c1" * 16))
    assert s == 200

    app2 = RegistryApp(
        RegistryStore(db_hk),
        hotkey_enroll_limit=2,
        hotkey_enroll_window_seconds=3600,
    )
    s, body = _call(app2, "POST", "/v1/enroll", _signed_payload(nonce="c2" * 16))
    assert s == 429
    assert "hotkey" in body["error"]


# ---------------------------------------------------------------------------
# Test 5: Hostname resolution gates network access
# ---------------------------------------------------------------------------

def test_endpoint_hostname_resolution_gates_network_access() -> None:
    with pytest.raises(ValueError, match="non-global"):
        _resolve_endpoint(
            "http://miner.internal.corp:8090",
            resolver=lambda h, p: ["192.168.0.1"],
        )

    with pytest.raises(ValueError, match="non-global"):
        _resolve_endpoint(
            "http://link.local.host:8090",
            resolver=lambda h, p: ["169.254.0.1"],
        )

    with pytest.raises(ValueError, match="non-global"):
        _resolve_endpoint(
            "http://lan-host:8090",
            resolver=lambda h, p: ["10.0.0.1"],
        )

    # Global IP resolution proceeds
    _resolve_endpoint(
        "http://miner.example.com:8090",
        resolver=lambda h, p: ["1.2.3.4"],
    )

    # IP literals are skipped
    _resolve_endpoint("http://127.0.0.1:8090")
    _resolve_endpoint("http://192.168.1.1:8090")

    # opener must NOT be called when resolution fails
    network_calls: list[str] = []

    class _TrackingOpener:
        def open(self, req, timeout=None):
            network_calls.append(getattr(req, "full_url", str(req)))
            raise OSError("simulated network error")

    with pytest.raises(ValueError, match="non-global"):
        _request_evidence(
            "http://miner.internal.corp:8090",
            "5" + "X" * 47,
            b"\x00" * 32,
            resolver=lambda h, p: ["10.0.0.1"],
            opener=_TrackingOpener(),
        )
    assert not network_calls

    # With global resolver, opener IS called
    with pytest.raises(OSError, match="simulated"):
        _request_evidence(
            "http://miner.example.com:8090",
            "5" + "Y" * 47,
            b"\x00" * 32,
            resolver=lambda h, p: ["1.2.3.4"],
            opener=_TrackingOpener(),
        )
    assert network_calls


# ---------------------------------------------------------------------------
# Test 6: Bounded concurrent probes isolate failures
# ---------------------------------------------------------------------------

def test_bounded_concurrent_probe_isolation(monkeypatch, tmp_path: Path) -> None:
    tdx_server = _serve(_TdxHandler)
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    failing_hotkeys = []
    for i in range(3):
        hk = "5" + chr(ord("F") + i) * 47
        failing_hotkeys.append(hk)
        store.enroll(hk, "http://127.0.0.1:9")

    valid_hk = _TdxHandler.hotkey
    store.enroll(valid_hk, f"http://127.0.0.1:{tdx_server.server_port}")

    monkeypatch.setattr("cathedral.prober.verifier.verify", _fake_tdx_verify)

    start = time.monotonic()
    probe_once(store, Policy(), max_workers=2)
    elapsed = time.monotonic() - start

    tdx_server.shutdown()

    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}

    for hk in failing_hotkeys:
        assert statuses[hk] == "FAILED"

    assert statuses[valid_hk] == "VERIFIED"
    assert board["count"] == 1
    assert elapsed < 5.0


# ---------------------------------------------------------------------------
# Test 7: Expired chip binding allows rotation; unexpired blocks
# ---------------------------------------------------------------------------

def test_expired_chip_binding_allows_rotation(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"), verification_ttl_seconds=60)
    hotkey_a = "5" + "P" * 47
    hotkey_b = "5" + "Q" * 47
    chip_id = "ef" * 32

    store.enroll(hotkey_a, "https://a.example.com")
    store.enroll(hotkey_b, "https://b.example.com")

    store.record_verdict(hotkey_a, _attested(chip_id, "meas"))

    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}
    assert statuses[hotkey_a] == "VERIFIED"

    # hotkey_b tries same chip while hotkey_a is live -> FAILED
    store.record_verdict(hotkey_b, _attested(chip_id, "meas"))
    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}
    assert statuses[hotkey_b] == "FAILED"

    # Expire hotkey_a
    with store._connect() as conn:
        conn.execute(
            "UPDATE attestations SET last_verified_iso = ? WHERE hotkey = ?",
            ("2000-01-01T00:00:00Z", hotkey_a),
        )

    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}
    assert statuses[hotkey_a] == "STALE"

    # hotkey_b can now claim the chip
    store.record_verdict(hotkey_b, _attested(chip_id, "meas"))
    board = store.board()
    statuses = {m["hotkey"]: m["verification_status"] for m in board["miners"]}
    assert statuses[hotkey_a] == "STALE"
    assert statuses[hotkey_b] == "VERIFIED"
    assert board["count"] == 1


# ---------------------------------------------------------------------------
# Test 8: JsonHotkeyRegistrationProvider unit cases
# ---------------------------------------------------------------------------

def test_json_provider_registered_and_unregistered(tmp_path: Path) -> None:
    hk_file = tmp_path / "hotkeys.json"
    hk_file.write_text(json.dumps([HOTKEY, "5OtherKey" + "A" * 39]))

    provider = JsonHotkeyRegistrationProvider(str(hk_file), max_age_seconds=3600)
    assert provider.is_registered(HOTKEY) is True
    assert provider.is_registered("5NotInFile" + "Z" * 38) is False


def test_json_provider_newline_format(tmp_path: Path) -> None:
    hk_file = tmp_path / "hotkeys.txt"
    hk_file.write_text(f"# registered hotkeys\n{HOTKEY}\n5Another" + "B" * 40 + "\n\n")

    provider = JsonHotkeyRegistrationProvider(str(hk_file), max_age_seconds=3600)
    assert provider.is_registered(HOTKEY) is True
    assert provider.is_registered("# registered hotkeys") is False
    assert provider.is_registered("5NotThere" + "Z" * 39) is False


def test_json_provider_stale_file(tmp_path: Path) -> None:
    hk_file = tmp_path / "hotkeys.json"
    hk_file.write_text(json.dumps([HOTKEY]))
    old_time = time.time() - 7200
    os.utime(str(hk_file), (old_time, old_time))

    provider = JsonHotkeyRegistrationProvider(str(hk_file), max_age_seconds=3600)
    result = provider.is_registered(HOTKEY)
    assert result is None


def test_json_provider_unreadable_file(tmp_path: Path) -> None:
    provider = JsonHotkeyRegistrationProvider(
        str(tmp_path / "nonexistent.json"), max_age_seconds=3600
    )
    assert provider.is_registered(HOTKEY) is None


# ---------------------------------------------------------------------------
# Test 9: Production mode with file provider
# ---------------------------------------------------------------------------

def test_production_mode_file_provider_allows_registered(tmp_path: Path) -> None:
    hk_file = tmp_path / "hotkeys.json"
    hk_file.write_text(json.dumps([HOTKEY]))

    provider = JsonHotkeyRegistrationProvider(str(hk_file), max_age_seconds=3600)
    app = RegistryApp(
        RegistryStore(str(tmp_path / "r.sqlite")),
        production_mode=True,
        registration_provider=provider,
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="e0" * 16, endpoint_url="https://8.8.8.8:8090"))
    assert status == 200
    assert body == {"status": "enrolled"}


def test_production_mode_file_provider_rejects_unregistered(tmp_path: Path) -> None:
    hk_file = tmp_path / "hotkeys.json"
    hk_file.write_text(json.dumps(["5OtherHotkey" + "X" * 36]))

    provider = JsonHotkeyRegistrationProvider(str(hk_file), max_age_seconds=3600)
    app = RegistryApp(
        RegistryStore(str(tmp_path / "r.sqlite")),
        production_mode=True,
        registration_provider=provider,
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="f0" * 16, endpoint_url="https://8.8.8.8:8090"))
    assert status == 403
    assert "not registered" in body["error"]


def test_production_mode_stale_file_fails_closed(tmp_path: Path) -> None:
    hk_file = tmp_path / "hotkeys.json"
    hk_file.write_text(json.dumps([HOTKEY]))
    old_time = time.time() - 7200
    os.utime(str(hk_file), (old_time, old_time))

    provider = JsonHotkeyRegistrationProvider(str(hk_file), max_age_seconds=3600)
    app = RegistryApp(
        RegistryStore(str(tmp_path / "r.sqlite")),
        production_mode=True,
        registration_provider=provider,
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="a0" * 16, endpoint_url="https://8.8.8.8:8090"))
    assert status == 403


def test_production_mode_missing_file_fails_closed(tmp_path: Path) -> None:
    provider = JsonHotkeyRegistrationProvider(
        str(tmp_path / "missing.json"), max_age_seconds=3600
    )
    app = RegistryApp(
        RegistryStore(str(tmp_path / "r.sqlite")),
        production_mode=True,
        registration_provider=provider,
    )
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="b0" * 16, endpoint_url="https://8.8.8.8:8090"))
    assert status == 403


# ---------------------------------------------------------------------------
# Test 10: Pre-resolved connector
# ---------------------------------------------------------------------------

def test_pre_resolved_connector_stores_original_hostname() -> None:
    conn = _PreResolvedHTTPConnection("miner.example.com:9000", resolved_addr="203.0.113.1")
    assert conn.host == "miner.example.com"
    assert conn.port == 9000
    assert conn._resolved_addr == "203.0.113.1"

    conn_s = _PreResolvedHTTPSConnection("miner.example.com:443", resolved_addr="203.0.113.1")
    assert conn_s.host == "miner.example.com"
    assert conn_s._resolved_addr == "203.0.113.1"


def test_pre_resolved_connector_uses_validated_ip(monkeypatch) -> None:
    connection_targets: list[tuple[str, int]] = []

    def spy_create_connection(addr, timeout=None, source_address=None):
        connection_targets.append(addr)
        raise ConnectionRefusedError("test sentinel")

    monkeypatch.setattr(_socket_module, "create_connection", spy_create_connection)

    with pytest.raises((ConnectionRefusedError, OSError)):
        _request_evidence(
            "http://miner.example.com:9000",
            "5" + "M" * 47,
            b"\x01" * 32,
            resolver=lambda h, p: ["1.1.1.1"],
        )

    assert connection_targets
    ip, port = connection_targets[0]
    assert ip == "1.1.1.1"
    assert port == 9000


def test_resolver_called_exactly_once(monkeypatch) -> None:
    resolver_calls: list[tuple[str, int]] = []
    connection_targets: list[tuple[str, int]] = []

    def tracking_resolver(host, port):
        resolver_calls.append((host, port))
        return ["1.1.1.1"]

    def spy_create_connection(addr, timeout=None, source_address=None):
        connection_targets.append(addr)
        raise ConnectionRefusedError("test sentinel")

    monkeypatch.setattr(_socket_module, "create_connection", spy_create_connection)

    with pytest.raises((ConnectionRefusedError, OSError)):
        _request_evidence(
            "http://miner.example.com:9001",
            "5" + "N" * 47,
            b"\x02" * 32,
            resolver=tracking_resolver,
        )

    assert len(resolver_calls) == 1
    assert connection_targets
    assert connection_targets[0][0] == "1.1.1.1"


# ---------------------------------------------------------------------------
# Test 11: max_workers validation
# ---------------------------------------------------------------------------

def test_max_workers_zero_raises_before_any_thread(tmp_path: Path) -> None:
    store = RegistryStore(str(tmp_path / "registry.sqlite"))

    with pytest.raises(ValueError, match=r"max_workers"):
        probe_once(store, Policy(), max_workers=0)

    with pytest.raises(ValueError, match=r"max_workers"):
        probe_once(store, Policy(), max_workers=-5)
