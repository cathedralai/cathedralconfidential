from __future__ import annotations

import io
import json

from cathedral.common import Attested, Tier
from cathedral.enroll import IpRateLimiter, RegistryApp, RegistryStore


HOTKEY = "5" + "A" * 47


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


def test_enroll_validates_hotkey_and_url(tmp_path):
    app = RegistryApp(RegistryStore(str(tmp_path / "registry.sqlite")))

    status, body = _call(app, "POST", "/v1/enroll", {"hotkey": "bad", "endpoint_url": "http://m"})
    assert status == 400
    assert "hotkey" in body["error"]

    status, body = _call(app, "POST", "/v1/enroll", {"hotkey": HOTKEY, "endpoint_url": "ftp://m"})
    assert status == 400
    assert "http" in body["error"]

    status, body = _call(
        app,
        "POST",
        "/v1/enroll",
        {"hotkey": HOTKEY, "endpoint_url": "http://127.0.0.1:8090"},
    )
    assert status == 200
    assert body == {"status": "enrolled"}


def test_enroll_rate_limits_by_ip(tmp_path):
    app = RegistryApp(
        RegistryStore(str(tmp_path / "registry.sqlite")),
        IpRateLimiter(limit=2, window_seconds=60),
    )
    payload = {"hotkey": HOTKEY, "endpoint_url": "http://127.0.0.1:8090"}

    assert _call(app, "POST", "/v1/enroll", payload)[0] == 200
    assert _call(app, "POST", "/v1/enroll", payload)[0] == 200
    status, body = _call(app, "POST", "/v1/enroll", payload)
    assert status == 429
    assert body["error"] == "rate limit exceeded"


def test_board_shape_and_chip_id_dedup_count(tmp_path):
    store = RegistryStore(str(tmp_path / "registry.sqlite"))
    hotkey_a = "5" + "A" * 47
    hotkey_b = "5" + "B" * 47
    chip_id = "0123456789abcdef" * 8
    store.enroll(hotkey_a, "http://127.0.0.1:8090/a")
    store.enroll(hotkey_b, "http://127.0.0.1:8090/b")
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
