"""Versioned REPORT_DATA and live TLS channel-binding contracts."""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from cathedral.channel import (
    ChannelBindingError,
    application_key_binding,
    extract_spki_der,
    tls_spki_binding,
)
from cathedral.common import (
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    report_data_v2,
)
from cathedral.lanes.sat import _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.worker import WorkerServer


HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"


def _binding(seed: int = 1) -> ChannelBinding:
    return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, bytes((seed,)) * 32)


def test_report_data_v2_is_deterministic_and_every_field_is_unambiguous():
    nonce = b"n" * 32
    binding = _binding()
    baseline = report_data_v2(nonce, "hotkey", binding)

    assert len(baseline) == 64
    assert report_data_v2(nonce, "hotkey", binding) == baseline
    assert report_data_v2(b"m" * 32, "hotkey", binding) != baseline
    assert report_data_v2(nonce, "hotkey-2", binding) != baseline
    assert report_data_v2(nonce, "hotkey", _binding(2)) != baseline
    application = ChannelBinding(
        ChannelBindingType.APPLICATION_KEY_SHA256, binding.digest
    )
    assert report_data_v2(nonce, "hotkey", application) != baseline
    # Length framing prevents concatenation ambiguity across adjacent fields.
    assert report_data_v2(nonce, "ab", binding) != report_data_v2(
        nonce, "a", binding
    )


@pytest.mark.parametrize(
    ("nonce", "hotkey", "binding"),
    [
        (b"short", "hotkey", _binding()),
        (b"n" * 32, "", _binding()),
        (b"n" * 32, "x" * 513, _binding()),
        (b"n" * 32, "hotkey", object()),
    ],
)
def test_report_data_v2_rejects_invalid_boundaries(nonce, hotkey, binding):
    with pytest.raises(ValueError):
        report_data_v2(nonce, hotkey, binding)


def test_evidence_rejects_unknown_or_incomplete_report_data_versions():
    common = dict(
        kind=EvidenceKind.TDX,
        quote=b"quote",
        nonce=b"n" * 32,
        miner_hotkey="hotkey",
    )
    with pytest.raises(ValueError, match="unsupported"):
        Evidence(**common, report_data_version=3)
    with pytest.raises(ValueError, match="requires"):
        Evidence(**common, report_data_version=2)
    with pytest.raises(ValueError, match="legacy"):
        Evidence(**common, channel_binding=_binding())


def test_application_key_binding_is_typed_and_key_sensitive():
    first = application_key_binding(b"application-public-key-1")
    second = application_key_binding(b"application-public-key-2")

    assert first.binding_type is ChannelBindingType.APPLICATION_KEY_SHA256
    assert first != second
    with pytest.raises(ChannelBindingError):
        application_key_binding(b"")


def test_public_launch_docs_require_protected_production_channel():
    launch = Path("docs/TDX_LAUNCH.md").read_text(encoding="utf-8")
    normalized = " ".join(launch.split())
    assert "Production endpoints use HTTPS" in normalized
    assert "before writing any request bytes" in normalized
    assert "Plain HTTP is limited to the explicit development loopback" in normalized
    assert "A public certificate by itself does not prove" in normalized


def test_remote_rejects_insecure_custom_tls_context():
    context = ssl._create_unverified_context()
    with pytest.raises(ValueError, match="verify certificates"):
        RemoteMiner("https://127.0.0.1:443", HOTKEY, ssl_context=context)


@pytest.mark.parametrize(
    "malformed",
    [b"", b"\x30\x80", b"\x30\x81\x01\x00", b"\x30\x03\x30\x01"],
)
def test_spki_parser_rejects_truncated_and_noncanonical_der(malformed):
    with pytest.raises(ChannelBindingError):
        extract_spki_der(malformed)


def _certificate_pair(directory: Path, name: str) -> tuple[Path, Path, bytes]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is required for the local TLS integration test")
    key = directory / f"{name}.key.pem"
    cert = directory / f"{name}.cert.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    certificate_der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    return cert, key, certificate_der


def _bound_evidence(
    nonce: bytes,
    hotkey: str,
    *,
    channel_binding: ChannelBinding,
    report_data_version: int,
) -> Evidence:
    assert report_data_version == 2
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=report_data_v2(nonce, hotkey, channel_binding),
        nonce=nonce,
        miner_hotkey=hotkey,
        report_data_version=2,
        channel_binding=channel_binding,
    )


def _sat_item() -> SatWorkItem:
    instance = SatInstance(2, [[1, 2], [-1, 2]])
    seed = 7
    return SatWorkItem(
        instance,
        seed,
        _compute_challenge_id(instance, seed),
    )


def test_tls_spki_binding_round_trip_before_protected_work(tmp_path: Path):
    cert, key, certificate_der = _certificate_pair(tmp_path, "worker")
    binding = tls_spki_binding(certificate_der)
    openssl = shutil.which("openssl")
    assert openssl is not None
    public_key_pem = subprocess.run(
        [openssl, "x509", "-in", str(cert), "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    public_key_der = subprocess.run(
        [openssl, "pkey", "-pubin", "-outform", "DER"],
        input=public_key_pem,
        check=True,
        capture_output=True,
    ).stdout
    assert extract_spki_der(certificate_der) == public_key_der
    with pytest.raises(ChannelBindingError):
        extract_spki_der(certificate_der + b"\x00")

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_evidence,
        channel_binding=binding,
        tls_context=server_context,
        allow_noncanonical_sat=True,
        bearer_token="protected-token",
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            bearer_token="protected-token",
            ssl_context=client_context,
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        assert evidence.channel_binding == binding
        assert remote.confirm_channel_binding(evidence) == binding
        certificate = remote.do_sat_work(_sat_item())

    assert certificate.assigned_hotkey == HOTKEY


def test_tls_worker_rejects_live_key_not_owned_by_attested_configuration(
    tmp_path: Path,
):
    cert, key, _ = _certificate_pair(tmp_path, "worker")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_evidence,
        channel_binding=_binding(),
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url, HOTKEY, ssl_context=client_context
        )
        with pytest.raises(RemoteError, match="HTTP 403"):
            remote.fetch_evidence(os.urandom(32))


def test_certificate_rotation_between_attestation_and_work_fails_before_dispatch(
    tmp_path: Path,
):
    cert_a, key_a, der_a = _certificate_pair(tmp_path, "worker-a")
    cert_b, key_b, _ = _certificate_pair(tmp_path, "worker-b")
    binding_a = tls_spki_binding(der_a)

    context_a = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_a.load_cert_chain(cert_a, key_a)
    context_b = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_b.load_cert_chain(cert_b, key_b)
    handshakes = 0

    def rotate(ssl_socket, _server_name, _initial_context):
        nonlocal handshakes
        handshakes += 1
        ssl_socket.context = context_a if handshakes == 1 else context_b

    context_a.set_servername_callback(rotate)
    client_context = ssl.create_default_context()
    client_context.load_verify_locations(cafile=str(cert_a))
    client_context.load_verify_locations(cafile=str(cert_b))

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_bound_evidence,
        channel_binding=binding_a,
        tls_context=context_a,
        allow_noncanonical_sat=True,
        bearer_token="must-not-be-sent-on-changed-key",
    ) as server:
        server._server.handle_error = lambda _request, _address: None
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            HOTKEY,
            bearer_token="must-not-be-sent-on-changed-key",
            ssl_context=client_context,
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)
        with pytest.raises(RemoteError, match="channel key changed"):
            remote.do_sat_work(_sat_item())

    assert handshakes == 2


def test_failed_fresh_evidence_attempt_clears_previously_trusted_binding(
    tmp_path: Path,
):
    cert, key, certificate_der = _certificate_pair(tmp_path, "worker")
    binding = tls_spki_binding(certificate_der)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))

    calls = 0

    def fail_second_collection(
        nonce: bytes,
        hotkey: str,
        *,
        channel_binding: ChannelBinding,
        report_data_version: int,
    ) -> Evidence:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated fresh-evidence failure")
        return _bound_evidence(
            nonce,
            hotkey,
            channel_binding=channel_binding,
            report_data_version=report_data_version,
        )

    with WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=fail_second_collection,
        channel_binding=binding,
        tls_context=server_context,
        allow_noncanonical_sat=True,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url, HOTKEY, ssl_context=client_context
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)
        with pytest.raises(RemoteError, match="HTTP 500"):
            remote.fetch_evidence(os.urandom(32))
        with pytest.raises(RemoteError, match="required before work"):
            remote.do_sat_work(_sat_item())
