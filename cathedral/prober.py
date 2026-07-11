"""Attestation probe loop for enrolled Cathedral miners."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPResponse
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import cathedral.verify as verifier
from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier, issue_nonce
from cathedral.enroll import RegistryStore


MAX_EVIDENCE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5
LOGGER = logging.getLogger(__name__)


class _PreResolvedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that uses a pre-resolved IP address.

    Stores the original hostname for the Host header and the resolved IP
    for the socket connection. This prevents a second DNS lookup that could
    be hijacked by DNS rebinding after enrollment-time validation.
    """

    def __init__(self, host: str, *, resolved_addr: str, **kwargs: Any) -> None:
        self._resolved_addr = resolved_addr
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        """Override socket connection to use the pre-resolved IP."""
        self.sock = socket.create_connection(
            (self._resolved_addr, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class _PreResolvedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that uses a pre-resolved IP address.

    Stores the original hostname for SNI and the resolved IP for the socket.
    """

    def __init__(self, host: str, *, resolved_addr: str, **kwargs: Any) -> None:
        self._resolved_addr = resolved_addr
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        """Override socket connection to use the pre-resolved IP."""
        sock = socket.create_connection(
            (self._resolved_addr, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            return
        self.sock = self._wrap_socket(
            sock,
            server_hostname=self.host,
        )


def _resolve_endpoint(url: str, *, resolver: Any = None, production_mode: bool = False) -> str | None:
    """Resolve the endpoint URL's hostname and verify every resolved address is
    a public/global unicast destination.  Runs before any network call to
    prevent SSRF to loopback, link-local, or RFC-1918 targets via DNS rebinding.

    IP literals are validated for globality here. At enrollment time,
    ``validate_endpoint_url`` enforces this in production_mode=True only. At
    probe time, this function ensures preexisting/migrated/hand-inserted rows
    cannot use local IP literals in production mode.

    :param resolver: optional ``callable(host: str, port: int) -> list[str]``
        injected by tests.  When None the default system resolver is used.
    :param production_mode: when True, both hostname and non-global IP-literal
        endpoints are rejected outright, before any network access. This
        closes two SSRF gaps: (1) DNS rebinding (hostname → non-global via
        re-resolution), and (2) stale enrollments (preexisting local IP
        literals that bypassed production enrollment checks). A public IP
        literal has neither gap because nothing is re-resolved and the literal
        is validated to be global at this point. Non-production callers accept
        local IP literals for testing; that residual SSRF window is accepted
        outside production.

    :return: the first validated global address (for use in pre-resolved
        connection classes), or None if the URL uses a global IP literal.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        raise ValueError("endpoint_url has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # IP literals: validate globality; in production mode, reject all non-global.
    try:
        ip = ipaddress.ip_address(host)
        if production_mode and not ip.is_global:
            raise ValueError(
                f"endpoint IP literal {host!r} rejected in production mode: "
                "must be a public/global address"
            )
        return None  # IP literal (validated as global in production); no resolution needed
    except ValueError as exc:
        # Re-raise validation errors; let hostname parsing continue.
        if "rejected" in str(exc):
            raise
        pass  # Not an IP literal — fall through.

    if production_mode:
        raise ValueError(
            f"endpoint hostname {host!r} rejected in production mode: "
            "production endpoints must be a public IP literal"
        )

    if resolver is not None:
        addrs = resolver(host, port)
    else:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(
                f"cannot resolve endpoint hostname {host!r}: {exc}"
            ) from exc
        addrs = [info[4][0] for info in infos]

    if not addrs:
        raise ValueError(f"endpoint hostname {host!r} resolved to no addresses")

    resolved_addr = None
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if not ip.is_global:
            raise ValueError(
                f"endpoint resolves to non-global address {addr!r} for hostname {host!r}"
            )
        if resolved_addr is None:
            resolved_addr = addr
    return resolved_addr


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _PreResolvedHTTPHandler(http.client.HTTPConnection):
    """urllib handler that uses pre-resolved HTTP connections."""

    def __init__(self, resolved_addr: str) -> None:
        self.resolved_addr = resolved_addr


class _PreResolvedHTTPSHandler(http.client.HTTPSConnection):
    """urllib handler that uses pre-resolved HTTPS connections."""

    def __init__(self, resolved_addr: str) -> None:
        self.resolved_addr = resolved_addr


def _build_pre_resolved_opener(resolved_addr: str) -> Any:
    """Build an opener that uses pre-resolved connection classes.

    The opener will instantiate _PreResolvedHTTPConnection and
    _PreResolvedHTTPSConnection with the validated resolved address,
    preventing any secondary DNS lookup that could be hijacked.
    """
    from urllib.request import HTTPHandler, HTTPSHandler

    class _ResolvedHTTPHandler(HTTPHandler):
        def http_open(self, req: Any) -> Any:
            # Extract host from request
            host = req.host
            return self.do_open(
                lambda h, **kw: _PreResolvedHTTPConnection(h, resolved_addr=resolved_addr, **kw),
                req,
            )

    class _ResolvedHTTPSHandler(HTTPSHandler):
        def https_open(self, req: Any) -> Any:
            host = req.host
            return self.do_open(
                lambda h, **kw: _PreResolvedHTTPSConnection(h, resolved_addr=resolved_addr, **kw),
                req,
            )

    return build_opener(NoRedirect, _ResolvedHTTPHandler(), _ResolvedHTTPSHandler())


def _read_capped(response: HTTPResponse, cap: int = MAX_EVIDENCE_BYTES) -> bytes:
    body = response.read(cap + 1)
    if len(body) > cap:
        raise ValueError("evidence response too large")
    return body


def _parse_evidence_item(raw: Any, hotkey: str, nonce: bytes) -> Evidence:
    if not isinstance(raw, dict):
        raise ValueError("evidence item must be an object")
    kind = EvidenceKind(raw["kind"])
    quote = base64.b64decode(raw["quote_b64"], validate=True)
    if len(quote) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence quote too large")
    evidence_nonce = bytes.fromhex(raw["nonce_hex"])
    if evidence_nonce != nonce:
        raise ValueError("evidence nonce mismatch")
    miner_hotkey = raw.get("miner_hotkey")
    if miner_hotkey != hotkey:
        raise ValueError("evidence hotkey mismatch")
    cert_chain = [base64.b64decode(item, validate=True) for item in raw.get("cert_chain_b64", [])]
    ssh_host_key = None
    if raw.get("ssh_host_key_b64"):
        ssh_host_key = base64.b64decode(raw["ssh_host_key_b64"], validate=True)
    return Evidence(
        kind=kind,
        quote=quote,
        nonce=evidence_nonce,
        miner_hotkey=miner_hotkey,
        cert_chain=cert_chain,
        ssh_host_key=ssh_host_key,
        composite_jwt=raw.get("composite_jwt"),
    )


def _request_evidence(
    endpoint_url: str,
    hotkey: str,
    nonce: bytes,
    *,
    resolver: Any = None,
    opener: Any = None,
    production_mode: bool = False,
) -> list[Evidence]:
    """Fetch attestation evidence from a miner endpoint.

    :param resolver: injected DNS resolver ``(host, port) -> list[str]`` for
        tests; None uses the system resolver.  See ``_resolve_endpoint``.
    :param opener: injected ``urllib`` opener for tests; None creates the
        default no-redirect opener with pre-resolved connection classes.
        The resolution check always runs first, before ``opener.open`` is
        ever called.
    :param production_mode: forwarded to ``_resolve_endpoint``; rejects
        hostname endpoints before any network access. See ``probe_once``.
    """
    # Resolve the hostname and reject non-global destinations before making
    # any network connection.  Prevents SSRF via DNS rebinding, and in
    # production mode rejects hostnames outright (see _resolve_endpoint).
    resolved_addr = _resolve_endpoint(
        endpoint_url, resolver=resolver, production_mode=production_mode
    )

    url = urljoin(endpoint_url.rstrip("/") + "/", "v1/evidence")
    payload = json.dumps({"nonce_hex": nonce.hex(), "hotkey": hotkey}).encode("utf-8")
    req = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    if opener is None:
        # Build a custom opener that uses pre-resolved connections to prevent
        # a second (rebindable) DNS lookup.  When resolved_addr is None
        # (IP literal endpoint), the standard connection classes are used.
        if resolved_addr is not None:
            opener = _build_pre_resolved_opener(resolved_addr)
        else:
            opener = build_opener(NoRedirect)
    with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
        body = _read_capped(response)
    raw = json.loads(body.decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evidence response must be an object")
    if isinstance(raw.get("evidence"), list):
        items = raw["evidence"]
    elif isinstance(raw.get("evidence_items"), list):
        items = raw["evidence_items"]
    else:
        items = [raw]
    if not items or len(items) > 8:
        raise ValueError("evidence bundle size invalid")
    return [_parse_evidence_item(item, hotkey, nonce) for item in items]


def policy_from_args(args: argparse.Namespace) -> Policy:
    measurements = set(args.allow_measurement or [])
    if args.allow_measurements_file:
        with open(args.allow_measurements_file) as fh:
            measurements.update(line.strip() for line in fh if line.strip())
    return Policy(allowed_measurements=measurements, min_tcb=args.min_tcb)


def _verify_tdx_evidence(
    evidences: list[Evidence],
    nonce: bytes,
    policy: Policy,
) -> Attested | None:
    """TDX-CPU launch path: a single verified TDX evidence is sufficient.

    Returns an ``Attested(CC_CPU_TDX)`` verdict only when the verifier returns
    an ``Attested`` with ``verification_status == "VERIFIED"`` and
    ``tier == Tier.CC_CPU_TDX``.  Any other outcome (None, wrong status, wrong
    tier) rejects.
    """
    tdx = next(
        (e for e in evidences if e.kind is EvidenceKind.TDX), None
    )
    if tdx is None:
        return None

    attested = verifier.verify(tdx, nonce, policy)
    if (
        attested is None
        or attested.verification_status != "VERIFIED"
        or attested.tier is not Tier.CC_CPU_TDX
    ):
        return None
    return attested


def verify_cc_evidence_bundle(
    evidences: list[Evidence],
    nonce: bytes,
    policy: Policy,
) -> Attested | None:
    """Verify an evidence bundle and return an admission verdict.

    Launch paths tried in order:

    1. **GPU composite** (SNP + GPU_CC): both must be VERIFIED.  GPU
       verification is intentionally still fail-closed -- until the NVIDIA
       NRAS or local verifier is wired in, ``verifier.verify`` returns
       ``None`` for GPU_CC evidence and this path cannot produce a verdict.

    2. **TDX-CPU**: a single TDX evidence with ``VERIFIED`` status and
       ``CC_CPU_TDX`` tier is sufficient.

    Returns ``None`` (reject) when no path produces a verdict.
    """

    # --- GPU composite path (fail-closed) ---
    snp = next((e for e in evidences if e.kind is EvidenceKind.SEV_SNP), None)
    gpu = next((e for e in evidences if e.kind is EvidenceKind.GPU_CC), None)
    if snp is not None and gpu is not None:
        snp_attested = verifier.verify(snp, nonce, policy)
        gpu_attested = verifier.verify(gpu, nonce, policy)
        if (
            snp_attested is not None
            and gpu_attested is not None
            and snp_attested.verification_status == "VERIFIED"
            and gpu_attested.verification_status == "VERIFIED"
        ):
            measurement = hashlib.sha256(
                f"snp:{snp_attested.measurement}\ngpu:{gpu_attested.measurement}".encode("utf-8")
            ).hexdigest()
            return Attested(
                tier=Tier.CC_GPU,
                chip_id=snp_attested.chip_id,
                measurement=measurement,
                tcb=min(snp_attested.tcb, gpu_attested.tcb),
            )

    # --- TDX-CPU path ---
    tdx_result = _verify_tdx_evidence(evidences, nonce, policy)
    if tdx_result is not None:
        return tdx_result

    return None


def probe_once(
    store: RegistryStore,
    policy: Policy,
    *,
    max_workers: int = 4,
    resolver: Any = None,
    opener: Any = None,
    production_mode: bool = False,
) -> None:
    """Probe all enrolled miners concurrently, bounded to *max_workers* threads.

    Each enrollment is isolated: a timeout or error in one probe records a
    FAILED verdict and does not prevent remaining enrollments from being probed
    in the same pass.  Concurrency prevents one slow miner from serialising
    the entire pass.

    :param production_mode: when True, any enrollment whose endpoint_url host
        is not a public IP literal is rejected before any network access
        (recorded as a FAILED verdict for that hotkey, isolated from the
        rest of the pass). Matches the production enrollment-time policy in
        ``cathedral.enroll.validate_endpoint_url``.
    :raises ValueError: when *max_workers* is less than 1.
    """
    if max_workers < 1:
        raise ValueError(f"max_workers must be at least 1, got {max_workers}")
    enrollments = store.enrollments()

    def _probe_one(enrollment: Any) -> None:
        nonce = issue_nonce()
        try:
            evidences = _request_evidence(
                enrollment.endpoint_url,
                enrollment.hotkey,
                nonce,
                resolver=resolver,
                opener=opener,
                production_mode=production_mode,
            )
            attested = verify_cc_evidence_bundle(evidences, nonce, policy)
            if attested is None:
                store.record_verdict(enrollment.hotkey, None, error="verification failed")
            else:
                store.record_verdict(enrollment.hotkey, attested)
        except Exception as exc:
            try:
                store.record_verdict(enrollment.hotkey, None, error=type(exc).__name__)
            except Exception:
                LOGGER.exception(
                    "failed to record probe failure for hotkey %s", enrollment.hotkey
                )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_probe_one, e) for e in enrollments]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                LOGGER.exception("unexpected error in probe worker")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Probe enrolled Cathedral miners for TEE evidence")
    parser.add_argument("--db", default="cathedral-enroll.sqlite")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--allow-measurement", action="append", default=[])
    parser.add_argument("--allow-measurements-file")
    parser.add_argument("--min-tcb", type=int, default=0)
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="concurrent probe workers per pass (default: 4, must be ≥ 1)",
    )
    parser.add_argument(
        "--production-mode",
        action="store_true",
        help=(
            "launch policy: reject enrollments whose endpoint host is not a "
            "public IP literal, before any network access (no DNS check/use gap)"
        ),
    )
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    store = RegistryStore(args.db)
    policy = policy_from_args(args)
    while True:
        try:
            probe_once(store, policy, max_workers=args.workers, production_mode=args.production_mode)
        except Exception:
            LOGGER.exception("probe pass failed")
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
