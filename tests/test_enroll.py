from __future__ import annotations

import io
import json
from base64 import b64encode
from datetime import UTC, datetime, timedelta

from substrateinterface import Keypair, KeypairType

from cathedral.common import Attested, Tier
from cathedral.enroll import (
    IpRateLimiter,
    RegistryApp,
    RegistryStore,
    canonical_enroll_payload,
    now_iso,
)


KEYPAIR = Keypair.create_from_uri("//Alice", crypto_type=KeypairType.SR25519)
HOTKEY = KEYPAIR.ss58_address


def _call(app: RegistryApp, method: str, path: str, payload: dict | None = None, ip: str = "1.2.3.4"):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "REMOTE_ADDR": ip,
    }
    seen = {}

    def start_response(status, headers):
        seen["status"] = status
        seen["headers"] = headers

    raw = b"".join(app(environ, start_response))
    return int(seen["status"].split()[0]), json.loads(raw.decode("utf-8"))


def _signed_payload(
    endpoint_url: str = "https://miner.example.com:8090",
    *,
    keypair: Keypair = KEYPAIR,
    hotkey: str = HOTKEY,
    nonce: str = "aa" * 16,
    timestamp: str | None = None,
) -> dict[str, str]:
    timestamp = timestamp if timestamp is not None else now_iso()
    message = canonical_enroll_payload(hotkey, endpoint_url, nonce, timestamp)
    signature = b64encode(keypair.sign(message)).decode("ascii")
    return {
        "hotkey": hotkey,
        "endpoint_url": endpoint_url,
        "nonce": nonce,
        "timestamp": timestamp,
        "signature_b64": signature,
    }


def test_enroll_validates_hotkey_and_url(tmp_path):
    app = RegistryApp(RegistryStore(str(tmp_path / "registry.sqlite")))

    status, body = _call(app, "POST", "/v1/enroll", {"hotkey": "bad", "endpoint_url": "http://m"})
    assert status == 400
    assert "hotkey" in body["error"]

    status, body = _call(app, "POST", "/v1/enroll", {"hotkey": HOTKEY, "endpoint_url": "ftp://m"})
    assert status == 400
    assert "http" in body["error"]

    status, body = _call(app, "POST", "/v1/enroll", _signed_payload())
    assert status == 200
    assert body == {"status": "enrolled"}


def test_enroll_rejects_unsigned_and_badly_signed_payloads(tmp_path):
    app = RegistryApp(RegistryStore(str(tmp_path / "registry.sqlite")))

    payload = _signed_payload()
    unsigned = dict(payload)
    unsigned.pop("signature_b64")
    status, body = _call(app, "POST", "/v1/enroll", unsigned)
    assert status == 400
    assert "signature" in body["error"]

    tampered = dict(payload)
    tampered["endpoint_url"] = "https://other-miner.example.com:8090"
    status, body = _call(app, "POST", "/v1/enroll", tampered)
    assert status == 400
    assert "signature" in body["error"]


def test_enroll_rejects_stale_timestamp_reused_nonce_and_private_hosts(tmp_path):
    app = RegistryApp(RegistryStore(str(tmp_path / "registry.sqlite")))
    stale = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0)
    payload = _signed_payload(timestamp=stale.isoformat().replace("+00:00", "Z"))

    status, body = _call(app, "POST", "/v1/enroll", payload)
    assert status == 400
    assert "timestamp" in body["error"]

    status, _body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="bb" * 16))
    assert status == 200
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="bb" * 16))
    assert status == 400
    assert "nonce" in body["error"]

    status, body = _call(
        app,
        "POST",
        "/v1/enroll",
        _signed_payload(endpoint_url="http://127.0.0.1:8090", nonce="cc" * 16),
    )
    assert status == 400
    assert "public address" in body["error"]


def test_enroll_rate_limits_by_ip(tmp_path):
    app = RegistryApp(
        RegistryStore(str(tmp_path / "registry.sqlite")),
        IpRateLimiter(limit=2, window_seconds=60),
    )

    assert _call(app, "POST", "/v1/enroll", _signed_payload(nonce="dd" * 16))[0] == 200
    assert _call(app, "POST", "/v1/enroll", _signed_payload(nonce="ee" * 16))[0] == 200
    status, body = _call(app, "POST", "/v1/enroll", _signed_payload(nonce="ff" * 16))
    assert status == 429
    assert body["error"] == "rate limit exceeded"


def test_board_shape_and_chip_id_dedup_rejects_second_hotkey(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"), verification_ttl_seconds=3600)
    hotkey_a = "5" + "A" * 47
    hotkey_b = "5" + "B" * 47
    chip_id = "0123456789abcdef" * 8
    store.enroll(hotkey_a, "https://a.example.com")
    store.enroll(hotkey_b, "https://b.example.com")
    store.record_verdict(hotkey_a, Attested(Tier.CC_CPU_SNP, chip_id, "m", 1))
    store.record_verdict(hotkey_b, Attested(Tier.CC_CPU_SNP, chip_id, "m", 1))

    board = store.board()

    assert board["count"] == 1
    assert len(board["miners"]) == 2
    assert board["miners"][0] == {
        "hotkey": hotkey_a,
        "chip_id_prefix": "0123456789abcdef",
        "tier": "cc_cpu_snp",
        "verification_status": "VERIFIED",
        "last_verified_iso": board["miners"][0]["last_verified_iso"],
    }
    assert board["miners"][1]["verification_status"] == "FAILED"


def test_verified_row_expires_from_board_count(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"), verification_ttl_seconds=1)
    hotkey = "5" + "C" * 47
    chip_id = "abcdef0123456789" * 8
    store.enroll(hotkey, "https://miner.example.com")
    store.record_verdict(hotkey, Attested(Tier.CC_CPU_SNP, chip_id, "m", 1))
    with store._connect() as conn:
        conn.execute(
            "UPDATE attestations SET last_verified_iso = ? WHERE hotkey = ?",
            ("2000-01-01T00:00:00Z", hotkey),
        )

    board = store.board()

    assert board["count"] == 0
    assert board["miners"][0]["verification_status"] == "STALE"
