"""Tests for cathedral/worker.py and cathedral/remote.py.

Covers:
- Good round trips (evidence + SAT work)
- Wrong IDs / hotkey / nonce → RemoteError
- Malformed / unknown / missing keys → 400
- Oversized request → 413 / oversized response → RemoteError
- Busy semaphore → 503
- Timeout / connection-failure isolation
- work_units never trusted (recomputed from instance)
- Optional bearer token DoS filter
- Returned certificate passes SatLane.verify()

All networking is loopback-only (127.0.0.1, OS-assigned port). No hardware.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cathedral.common import Evidence, EvidenceKind
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.worker import WorkerServer

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
OTHER_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"


def _fake_evidence(nonce: bytes, hotkey: str) -> Evidence:
    """Deterministic mock collector — no hardware needed."""
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=b"fakequote:" + nonce[:4],
        nonce=nonce,
        miner_hotkey=hotkey,
        cert_chain=[b"fakecert"],
    )


def _make_sat_item(n_vars: int = 3, seed: int = 0) -> SatWorkItem:
    clauses = [[1, 2], [-1, 3], [-2, -3]]
    inst = SatInstance(n_vars=n_vars, clauses=clauses)
    cid = _compute_challenge_id(inst, seed)
    return SatWorkItem(instance=inst, seed=seed, challenge_id=cid)


def _start_server(server: WorkerServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _post_raw(url: str, body: bytes, *, bearer: str | None = None) -> tuple[int, bytes]:
    """Return (status_code, body_bytes) without raising on 4xx/5xx."""
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# ---------------------------------------------------------------------------
# Good round trips
# ---------------------------------------------------------------------------

def test_evidence_good_round_trip():
    nonce = os.urandom(32)
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        ev = remote.fetch_evidence(nonce)

    assert isinstance(ev, Evidence)
    assert ev.kind == EvidenceKind.TDX
    assert ev.nonce == nonce
    assert ev.miner_hotkey == HOTKEY
    assert ev.quote == b"fakequote:" + nonce[:4]
    assert ev.cert_chain == [b"fakecert"]


def test_sat_work_good_round_trip():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        cert = remote.do_sat_work(item)

    assert isinstance(cert, SatCertificate)
    assert cert.satisfiable is True
    assert cert.challenge_id == item.challenge_id
    assert cert.miner_hotkey == HOTKEY
    # Verify the assignment is actually satisfying
    true_lits = set(cert.assignment)
    for clause in item.instance.clauses:
        assert any(lit in true_lits for lit in clause), f"clause {clause} not satisfied"


def test_evidence_with_bearer_good_round_trip():
    nonce = os.urandom(32)
    token = "s3cr3t-t0ken"
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token=token) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY, bearer_token=token)
        ev = remote.fetch_evidence(nonce)
    assert ev.miner_hotkey == HOTKEY


# ---------------------------------------------------------------------------
# Hotkey / nonce / challenge_id verification
# ---------------------------------------------------------------------------

def test_evidence_wrong_hotkey_in_response_rejected():
    """Worker using wrong-hotkey collector; RemoteMiner must detect mismatch."""
    nonce = os.urandom(32)

    def wrong_hotkey_collector(nonce: bytes, hotkey: str) -> Evidence:
        return _fake_evidence(nonce, OTHER_HOTKEY)  # returns wrong hotkey

    with WorkerServer(evidence_collector=wrong_hotkey_collector) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        with pytest.raises(RemoteError, match="hotkey mismatch"):
            remote.fetch_evidence(nonce)


def test_evidence_wrong_nonce_in_response_rejected():
    """Collector that returns a different nonce; RemoteMiner must detect it."""
    nonce = os.urandom(32)
    other_nonce = os.urandom(32)

    def wrong_nonce_collector(nonce: bytes, hotkey: str) -> Evidence:
        return _fake_evidence(other_nonce, hotkey)

    with WorkerServer(evidence_collector=wrong_nonce_collector) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        with pytest.raises(RemoteError, match="nonce mismatch"):
            remote.fetch_evidence(nonce)


def test_sat_wrong_challenge_id_response_rejected():
    """A fake server that echoes a different challenge_id; RemoteMiner rejects."""
    item = _make_sat_item()

    # Spin a one-off server that returns wrong challenge_id in response.
    class _FakeHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps({
                "satisfiable": True,
                "assignment": [1, -2, 3],
                "work_units": 3.0,
                "challenge_id": "wrong-id-000",
                "miner_hotkey": HOTKEY,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _FakeHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        with pytest.raises(RemoteError, match="challenge_id mismatch"):
            remote.do_sat_work(item)
    finally:
        fake_srv.shutdown()


def test_sat_wrong_challenge_id_request_rejected():
    """challenge_id that doesn't match instance+seed → 400 from worker."""
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "challenge_id": "badbadbadbad",  # wrong
            "assigned_hotkey": HOTKEY,
            "instance": {"n_vars": item.instance.n_vars, "clauses": item.instance.clauses},
            "seed": item.seed,
        }).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400
    assert b"challenge_id" in body


# ---------------------------------------------------------------------------
# Malformed / unknown / missing keys
# ---------------------------------------------------------------------------

def test_evidence_malformed_json_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", b"{not valid json")
    assert code == 400
    assert b"invalid JSON" in body


def test_evidence_unknown_key_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "nonce_hex": os.urandom(32).hex(),
            "assigned_hotkey": HOTKEY,
            "extra_field": "surprise",  # unknown
        }).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400
    assert b"schema" in body.lower() or b"extra" in body.lower()


def test_evidence_missing_key_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({"nonce_hex": os.urandom(32).hex()}).encode()  # missing assigned_hotkey
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400


def test_sat_work_unknown_key_rejected():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "challenge_id": item.challenge_id,
            "assigned_hotkey": HOTKEY,
            "instance": {"n_vars": item.instance.n_vars, "clauses": item.instance.clauses},
            "seed": item.seed,
            "injected": "evil",  # unknown
        }).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_sat_work_missing_key_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "challenge_id": "someid",
            "assigned_hotkey": HOTKEY,
            # missing instance and seed
        }).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_sat_work_instance_unknown_key_rejected():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "challenge_id": item.challenge_id,
            "assigned_hotkey": HOTKEY,
            "instance": {
                "n_vars": item.instance.n_vars,
                "clauses": item.instance.clauses,
                "surprise": True,  # unknown instance key
            },
            "seed": item.seed,
        }).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_unknown_path_returns_404():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        code, _ = _post_raw(f"{srv.base_url}/v1/unknown", b"{}")
    assert code == 404


def test_evidence_invalid_nonce_hex_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "nonce_hex": "not-hex!",
            "assigned_hotkey": HOTKEY,
        }).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400
    assert b"hex" in body.lower()


def test_evidence_empty_hotkey_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({
            "nonce_hex": os.urandom(32).hex(),
            "assigned_hotkey": "",
        }).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400


# ---------------------------------------------------------------------------
# Oversized request / response
# ---------------------------------------------------------------------------

def test_oversized_request_rejected():
    """Body exceeding max_body → 413."""
    with WorkerServer(evidence_collector=_fake_evidence, max_body=64) as srv:
        _start_server(srv)
        big_payload = json.dumps({
            "nonce_hex": "aa" * 32,
            "assigned_hotkey": "A" * 200,  # push it over 64 bytes
        }).encode()
        assert len(big_payload) > 64
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", big_payload)
    assert code == 413
    assert b"large" in body.lower()


def test_oversized_response_rejected():
    """Server returning >max_response_body bytes → RemoteError."""

    class _BigHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            # Return a valid-looking but enormous response
            big = json.dumps({
                "kind": "tdx",
                "quote_hex": "aa" * 70_000,  # ~140KB hex
                "nonce_hex": "bb" * 32,
                "miner_hotkey": HOTKEY,
                "cert_chain_hex": [],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(big)))
            self.end_headers()
            self.wfile.write(big)

    fake_srv = HTTPServer(("127.0.0.1", 0), _BigHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY, max_response_body=1024)  # tiny cap
        with pytest.raises(RemoteError, match="cap"):
            remote.fetch_evidence(os.urandom(32))
    finally:
        fake_srv.shutdown()


# ---------------------------------------------------------------------------
# Busy (semaphore / 503)
# ---------------------------------------------------------------------------

def test_busy_returns_503():
    """When the server is processing one request, a second gets 503."""
    hold = threading.Event()
    unblock = threading.Event()

    def blocking_collector(nonce: bytes, hotkey: str) -> Evidence:
        hold.set()           # signal: request is in flight
        unblock.wait(5.0)    # hold the semaphore
        return _fake_evidence(nonce, hotkey)

    with WorkerServer(evidence_collector=blocking_collector, max_concurrent=1) as srv:
        _start_server(srv)

        nonce_hex = os.urandom(32).hex()
        payload = json.dumps({"nonce_hex": nonce_hex, "assigned_hotkey": HOTKEY}).encode()
        url = f"{srv.base_url}/v1/evidence"

        # First request — runs in background, holds semaphore.
        results: list[tuple[int, bytes]] = []

        def first_request():
            results.append(_post_raw(url, payload))

        t1 = threading.Thread(target=first_request)
        t1.start()

        # Wait until first request is inside the handler.
        hold.wait(timeout=5.0)

        # Second request — should get 503 immediately.
        code2, body2 = _post_raw(url, payload)
        assert code2 == 503
        assert b"busy" in body2.lower()

        # Let first request finish.
        unblock.set()
        t1.join(timeout=5.0)
        assert results[0][0] == 200


# ---------------------------------------------------------------------------
# Timeout / connection-failure isolation
# ---------------------------------------------------------------------------

def test_timeout_raises_remote_error():
    """RemoteMiner wraps socket timeout as RemoteError; other operations unaffected."""
    # Find a free port then close the socket so nothing is listening.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    remote = RemoteMiner(f"http://127.0.0.1:{dead_port}", HOTKEY, timeout=0.5)
    with pytest.raises(RemoteError):
        remote.fetch_evidence(os.urandom(32))


def test_connection_error_does_not_leak_exception_type():
    """RemoteError wraps urllib errors; callers never see raw urllib exceptions."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    remote = RemoteMiner(f"http://127.0.0.1:{dead_port}", HOTKEY, timeout=0.5)
    with pytest.raises(RemoteError):
        remote.do_sat_work(_make_sat_item())


def test_one_failure_does_not_affect_next_request():
    """Failure on one call does not break the RemoteMiner for subsequent calls."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    remote_dead = RemoteMiner(f"http://127.0.0.1:{dead_port}", HOTKEY, timeout=0.3)
    with pytest.raises(RemoteError):
        remote_dead.fetch_evidence(os.urandom(32))

    # A second client to a live server should still work.
    nonce = os.urandom(32)
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote_live = RemoteMiner(srv.base_url, HOTKEY)
        ev = remote_live.fetch_evidence(nonce)
    assert ev.nonce == nonce


# ---------------------------------------------------------------------------
# work_units never trusted
# ---------------------------------------------------------------------------

def test_work_units_not_trusted():
    """RemoteMiner discards server work_units and recomputes from the instance."""
    item = _make_sat_item()
    expected_wu = float(len(item.instance.clauses))

    # Fake server that returns an inflated work_units.
    class _InflatedHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps({
                "satisfiable": True,
                "assignment": [1, 2, 3],
                "work_units": 1e300,  # forged / inflated
                "challenge_id": item.challenge_id,
                "miner_hotkey": HOTKEY,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _InflatedHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        cert = remote.do_sat_work(item)
        # Must equal the validator-recomputed value, not the forged 1e300.
        assert cert.work_units == expected_wu
    finally:
        fake_srv.shutdown()


# ---------------------------------------------------------------------------
# Bearer token DoS filter
# ---------------------------------------------------------------------------

def test_bearer_token_missing_returns_401():
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="tok") as srv:
        _start_server(srv)
        payload = json.dumps({"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload, bearer=None)
    assert code == 401
    assert b"unauthorized" in body.lower()


def test_bearer_token_wrong_returns_401():
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="correct") as srv:
        _start_server(srv)
        payload = json.dumps({"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/evidence", payload, bearer="wrong")
    assert code == 401


def test_bearer_token_correct_accepted():
    nonce = os.urandom(32)
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="mysecret") as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY, bearer_token="mysecret")
        ev = remote.fetch_evidence(nonce)
    assert ev.miner_hotkey == HOTKEY


# ---------------------------------------------------------------------------
# Response schema violations (extra / missing keys in server response)
# ---------------------------------------------------------------------------

def test_extra_key_in_evidence_response_raises_remote_error():
    """If the server adds an unexpected key, RemoteMiner raises RemoteError."""

    class _ExtraKeyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length))
            body = json.dumps({
                "kind": "tdx",
                "quote_hex": "aa" * 4,
                "nonce_hex": req["nonce_hex"],
                "miner_hotkey": req["assigned_hotkey"],
                "cert_chain_hex": [],
                "surprise_field": "evil",  # extra
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _ExtraKeyHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        with pytest.raises(RemoteError, match="schema"):
            remote.fetch_evidence(os.urandom(32))
    finally:
        fake_srv.shutdown()


def test_missing_key_in_sat_response_raises_remote_error():
    """If the server omits a required key, RemoteMiner raises RemoteError."""
    item = _make_sat_item()

    class _MissingKeyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps({
                "satisfiable": True,
                "assignment": [1, 2, 3],
                # missing: work_units, challenge_id, miner_hotkey
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _MissingKeyHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        with pytest.raises(RemoteError, match="schema"):
            remote.do_sat_work(item)
    finally:
        fake_srv.shutdown()


# ---------------------------------------------------------------------------
# Compatibility: returned certificate passes SatLane.verify()
# ---------------------------------------------------------------------------

def test_certificate_passes_sat_lane_verify():
    """Certificate from RemoteMiner is accepted by SatLane.verify()."""
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        cert = remote.do_sat_work(item)

    lane = SatLane()
    # Simulate lane having dispatched this item.
    lane._issued_ids.add(item.challenge_id)
    lane._challenge_owner[item.challenge_id] = HOTKEY

    verified = lane.verify(item, cert)
    assert verified is not None
    assert verified.satisfiable is True
    assert verified.challenge_id == item.challenge_id


def test_certificate_scores_correctly_in_lane():
    """SatLane.score() sums verified work for the correct miner."""
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        cert = remote.do_sat_work(item)

    lane = SatLane()
    lane._issued_ids.add(item.challenge_id)
    lane._challenge_owner[item.challenge_id] = HOTKEY
    verified = lane.verify(item, cert)
    assert verified is not None

    score = lane.score(HOTKEY, [verified])
    assert score == float(len(item.instance.clauses))
    # Other miner gets zero.
    assert lane.score(OTHER_HOTKEY, [verified]) == 0.0


def test_sat_miner_hotkey_field_backward_compat():
    """SatCertificate.miner_hotkey defaults to '' — existing construction still works."""
    from cathedral.lanes.sat_types import SatCertificate
    cert = SatCertificate(
        satisfiable=True,
        assignment=[1, 2, 3],
        work_units=3.0,
        challenge_id="abc",
    )
    assert cert.miner_hotkey == ""


def test_remote_miner_empty_hotkey_raises():
    with pytest.raises(ValueError, match="hotkey"):
        RemoteMiner("http://127.0.0.1:9999", "")
