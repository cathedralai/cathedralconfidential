from __future__ import annotations

import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from cathedral.channel import tls_spki_binding
from cathedral.policy_registry import verify_registry
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.runtime import RuntimeConfig
from scripts import tdx_cpu_launch_canary as canary


MEASUREMENT = "tdx-measurement-sha256:" + "a" * 64


def _certificate(
    common_name: str,
    *,
    issuer_key: Ed25519PrivateKey | None = None,
    issuer: x509.Certificate | None = None,
    ca: bool = False,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 7, 1, tzinfo=UTC))
        .not_valid_after(datetime(2026, 7, 1, tzinfo=UTC) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(issuer_key or key, algorithm=None)
    )
    return key, certificate


def _write_certificate(path, certificate: x509.Certificate) -> None:  # noqa: ANN001
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def test_fresh_canary_registry_is_strict_signed_and_receipt_authorized() -> None:
    policy_seed = bytes(range(32))
    receipt_seed = bytes(range(32, 64))
    document = canary.build_registry(
        [MEASUREMENT],
        policy_seed,
        receipt_seed,
        now=datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC),
    )

    snapshot = verify_registry(
        document,
        {canary._POLICY_KEY_ID: canary._public_key(policy_seed)},
        now=datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC),
        max_age_seconds=3600,
    )
    policy = snapshot.to_policy(
        at=datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC),
        max_age_seconds=3600,
    )

    assert policy.production_ready_at(datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC))
    assert policy.allowed_measurements == {MEASUREMENT}
    assert policy.tdx_allowed_tcb_statuses == {"UpToDate"}
    assert policy.tdx_allowed_advisories == set()
    assert len(snapshot.receipt_signing_keys) == 1
    assert snapshot.receipt_signing_keys[0].key_id == canary._RECEIPT_KEY_ID


@pytest.mark.parametrize(
    "measurements",
    [
        [],
        ["sample"],
        [MEASUREMENT, MEASUREMENT],
    ],
)
def test_canary_registry_rejects_missing_malformed_or_duplicate_measurements(
    measurements: list[str],
) -> None:
    with pytest.raises(canary.LaunchCanaryError):
        canary.build_registry(measurements, b"p" * 32, b"r" * 32)


def test_tls_pin_requires_one_regular_valid_pem_certificate(tmp_path) -> None:
    certificate = tmp_path / "worker.pem"
    certificate.write_text("not a certificate")

    with pytest.raises(canary.LaunchCanaryError, match="exactly one"):
        canary.build_tls_pin(certificate)

    _key, valid = _certificate("worker.example")
    certificate.write_bytes(
        valid.public_bytes(serialization.Encoding.PEM)
        + valid.public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(canary.LaunchCanaryError, match="exactly one"):
        canary.build_tls_pin(certificate)


def test_tls_pin_is_hostname_verifying_tls_12_and_exact_spki(monkeypatch, tmp_path) -> None:
    certificate_path = tmp_path / "worker.pem"
    _key, certificate = _certificate("worker.example")
    _write_certificate(certificate_path, certificate)
    loaded: list[str] = []

    class FakeContext:
        minimum_version = None
        verify_mode = None
        check_hostname = False

        def load_verify_locations(self, *, cadata: str) -> None:
            loaded.append(cadata)

    fake = FakeContext()
    monkeypatch.setattr(canary.ssl, "SSLContext", lambda _protocol: fake)

    pin = canary.build_tls_pin(certificate_path)

    assert pin.context is fake
    assert fake.minimum_version is ssl.TLSVersion.TLSv1_2
    assert fake.verify_mode is ssl.CERT_REQUIRED
    assert fake.check_hostname is True
    assert len(loaded) == 1
    assert hashlib.sha256(loaded[0].encode()).digest()
    assert pin.binding == tls_spki_binding(certificate.public_bytes(serialization.Encoding.DER))


def test_pinned_remote_rejects_alternate_leaf_from_trusted_ca(monkeypatch, tmp_path) -> None:
    ca_key, ca_certificate = _certificate("canary-root.example", ca=True)
    _leaf_key, alternate_leaf = _certificate(
        "worker.example",
        issuer_key=ca_key,
        issuer=ca_certificate,
    )
    ca_certificate.public_key().verify(
        alternate_leaf.signature,
        alternate_leaf.tbs_certificate_bytes,
    )
    ca_path = tmp_path / "endpoint.pem"
    _write_certificate(ca_path, ca_certificate)
    pin = canary.build_tls_pin(ca_path)
    observed = tls_spki_binding(alternate_leaf.public_bytes(serialization.Encoding.DER))
    monkeypatch.setattr(
        RemoteMiner,
        "fetch_evidence_bundle",
        lambda _self, _nonce: (SimpleNamespace(channel_binding=observed),),
    )
    remote = canary._PinnedRemoteMiner(
        "https://worker.example",
        "worker-hotkey",
        expected_binding=pin.binding,
        ssl_context=pin.context,
    )

    with pytest.raises(RemoteError, match="pinned endpoint certificate"):
        remote.fetch_evidence_bundle(b"n" * 32)


def test_pinned_remote_accepts_exact_endpoint_spki(monkeypatch, tmp_path) -> None:
    _key, certificate = _certificate("worker.example")
    certificate_path = tmp_path / "worker.pem"
    _write_certificate(certificate_path, certificate)
    pin = canary.build_tls_pin(certificate_path)
    evidence = SimpleNamespace(channel_binding=pin.binding)
    monkeypatch.setattr(
        RemoteMiner,
        "fetch_evidence_bundle",
        lambda _self, _nonce: (evidence,),
    )
    remote = canary._PinnedRemoteMiner(
        "https://worker.example",
        "worker-hotkey",
        expected_binding=pin.binding,
        ssl_context=pin.context,
    )

    assert remote.fetch_evidence_bundle(b"n" * 32) == (evidence,)


def test_tls_pin_map_uses_runtime_endpoint_canonicalization(tmp_path) -> None:
    _canary_key, canary_certificate = _certificate("canary.example")
    _worker_key, worker_certificate = _certificate("worker.example")
    canary_path = tmp_path / "canary.pem"
    worker_path = tmp_path / "worker.pem"
    _write_certificate(canary_path, canary_certificate)
    _write_certificate(worker_path, worker_certificate)
    config = RuntimeConfig(production_mode=True)

    pins = canary.build_tls_pins(
        "https://8.8.8.8:443/",
        canary_path,
        "https://1.1.1.1:443",
        worker_path,
        config,
    )

    assert set(pins) == {"https://8.8.8.8", "https://1.1.1.1"}
    remote = canary._remote_factory(pins)("https://8.8.8.8", "canary-hotkey")
    assert isinstance(remote, canary._PinnedRemoteMiner)
    assert remote._ssl_context is pins["https://8.8.8.8"].context


def test_tls_pin_map_rejects_canonically_equivalent_endpoints(tmp_path) -> None:
    _canary_key, canary_certificate = _certificate("canary.example")
    _worker_key, worker_certificate = _certificate("worker.example")
    canary_path = tmp_path / "canary.pem"
    worker_path = tmp_path / "worker.pem"
    _write_certificate(canary_path, canary_certificate)
    _write_certificate(worker_path, worker_certificate)

    with pytest.raises(canary.LaunchCanaryError, match="endpoints must differ"):
        canary.build_tls_pins(
            "https://8.8.8.8:443",
            canary_path,
            "https://8.8.8.8/",
            worker_path,
            RuntimeConfig(production_mode=True),
        )
