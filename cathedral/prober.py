"""Attestation probe loop for enrolled Cathedral miners."""

from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from http.client import HTTPResponse
from typing import Any, Callable
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import cathedral.verify as verifier
from cathedral.assurance import ATTESTATION_ADMISSION_POLICY, with_verified_channel
from cathedral.common import (
    Attested,
    Evidence,
    EvidenceKind,
    MAX_EVIDENCE_RESPONSE_BODY,
    MAX_GPU_EVIDENCE_CONCURRENCY,
    Policy,
    Tier,
    issue_nonce,
    is_globally_routable,
)
from cathedral.enroll import RegistryStore
from cathedral.lifecycle import (
    LifecycleError,
    LifecycleReason,
    WorkerLifecycleState,
)
from cathedral.remote import RemoteMiner


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


def _resolve_endpoint(
    url: str, *, resolver: Any = None, production_mode: bool = False
) -> str | None:
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
        if production_mode and not is_globally_routable(ip):
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
            raise ValueError(f"cannot resolve endpoint hostname {host!r}: {exc}") from exc
        addrs = [info[4][0] for info in infos]

    if not addrs:
        raise ValueError(f"endpoint hostname {host!r} resolved to no addresses")

    resolved_addr = None
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if not is_globally_routable(ip):
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
            return self.do_open(
                lambda h, **kw: _PreResolvedHTTPConnection(h, resolved_addr=resolved_addr, **kw),
                req,
            )

    class _ResolvedHTTPSHandler(HTTPSHandler):
        def https_open(self, req: Any) -> Any:
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
    return Policy(
        allowed_measurements=measurements,
        min_tcb=args.min_tcb,
        tdx_strict=getattr(args, "tdx_strict", False),
        tdx_allowed_tcb_statuses=set(getattr(args, "allow_tdx_tcb_status", None) or ["UpToDate"]),
        tdx_allowed_advisories=set(getattr(args, "allow_tdx_advisory", None) or []),
    )


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
    tdx = next((e for e in evidences if e.kind is EvidenceKind.TDX), None)
    if tdx is None:
        return None

    attested = verifier.verify(tdx, nonce, policy)
    if (
        attested is None
        or attested.verification_status != "VERIFIED"
        or attested.tier is not Tier.CC_CPU_TDX
        or not ATTESTATION_ADMISSION_POLICY.allows(attested.assurance)
    ):
        return None
    return attested


def verify_cc_evidence_bundle(
    evidences: list[Evidence],
    nonce: bytes,
    policy: Policy,
    *,
    gpu_profile=None,
    gpu_verifier=None,
    gpu_identity_registry=None,
    expected_tier: Tier = Tier.CC_CPU_TDX,
) -> Attested | None:
    """Verify the CPU evidence bundle and return an admission verdict.

    GPU verification is deliberately completed inside ``probe_once`` so the
    component result cannot escape without live-channel confirmation and the
    durable identity claim at the lifecycle admission boundary.

    Returns ``None`` (reject) when no path produces a verdict.
    """

    if expected_tier not in {Tier.CC_CPU_TDX, Tier.CC_GPU}:
        return None
    gpu_configuration = (gpu_profile, gpu_verifier, gpu_identity_registry)
    if expected_tier is Tier.CC_GPU:
        return None
    if any(item is not None for item in gpu_configuration):
        # CPU and GPU participation use separate validator-owned requests.
        return None

    gpu_components = [e for e in evidences if e.kind is EvidenceKind.GPU_CC]
    if gpu_components:
        return None

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
    policy_refresher: Callable[[], Policy] | None = None,
    gpu_profile=None,
    gpu_verifier=None,
    gpu_identity_registry=None,
    expected_tier: Tier = Tier.CC_CPU_TDX,
) -> bool:
    """Probe all enrolled miners concurrently, bounded to *max_workers* threads.

    Each enrollment is isolated: a timeout or transport error in one probe
    records a failed public verdict plus a bounded lifecycle retry and does not
    prevent remaining enrollments from being probed in the same pass.
    Concurrency prevents one slow miner from serialising the entire pass.

    :param production_mode: when True, any enrollment whose endpoint_url host
        is not a public IP literal is rejected before any network access
        (recorded as a FAILED verdict for that hotkey, isolated from the
        rest of the pass). Matches the production enrollment-time policy in
        ``cathedral.enroll.validate_endpoint_url``.
    :raises ValueError: when *max_workers* is less than 1.
    """
    if max_workers < 1:
        raise ValueError(f"max_workers must be at least 1, got {max_workers}")
    gpu_configuration = (gpu_profile, gpu_verifier, gpu_identity_registry)
    if expected_tier is Tier.CC_GPU and any(item is None for item in gpu_configuration):
        raise ValueError("GPU probing requires profile, verifier, and identity registry")
    if expected_tier is Tier.CC_CPU_TDX and any(item is not None for item in gpu_configuration):
        raise ValueError("CPU probing cannot carry GPU verifier configuration")
    if expected_tier not in {Tier.CC_CPU_TDX, Tier.CC_GPU}:
        raise ValueError("unsupported expected attestation tier")
    if expected_tier is Tier.CC_GPU:
        from cathedral.gpu import (
            ExternalGpuVerifier,
            GpuIdentityRegistry,
            GpuProfile,
        )

        if not isinstance(gpu_profile, GpuProfile) or not isinstance(
            gpu_identity_registry, GpuIdentityRegistry
        ):
            raise ValueError("GPU probe profile or identity registry is invalid")
    if production_mode:
        if not policy.production_ready_for_tdx:
            raise ValueError(
                "production probing requires strict signed CPU policy registry authority"
            )
        if policy_refresher is None:
            raise ValueError("production probing requires a live policy registry refresher")
        verifier.preflight_tdx_verifier(policy)

    captured_policy_authority = policy.registry_authority_identity

    def _require_current_policy() -> Policy:
        if not production_mode:
            return policy
        assert policy_refresher is not None
        refreshed = policy_refresher()
        if not isinstance(refreshed, Policy) or not refreshed.production_ready_for_tdx:
            raise ValueError("production CPU policy registry authority is not live")
        if refreshed.registry_authority_identity != captured_policy_authority:
            raise ValueError("production CPU policy changed during the probe")
        return refreshed

    _require_current_policy()
    if expected_tier is Tier.CC_GPU:
        if production_mode:
            if not gpu_profile.production_ready_for(policy):
                raise ValueError(
                    "production GPU probe requires a live profile from its CPU policy registry"
                )
            if not gpu_identity_registry.production_ready:
                raise ValueError("production GPU probe requires a protected identity registry")
            if not isinstance(gpu_verifier, ExternalGpuVerifier):
                raise ValueError("production GPU probe requires the pinned external verifier")
            if not gpu_verifier.production_ready:
                raise ValueError("production GPU probe requires a static verifier executable")
            gpu_verifier.preflight(gpu_profile)
    due_snapshots = {
        snapshot.hotkey: snapshot
        for snapshot in store.due_refreshes(refresh_ahead_seconds=store.verification_ttl_seconds)
    }
    probe_targets = [
        (enrollment, due_snapshots[enrollment.hotkey])
        for enrollment in store.enrollments()
        if enrollment.hotkey in due_snapshots
    ]
    gpu_evidence_slots = threading.BoundedSemaphore(MAX_GPU_EVIDENCE_CONCURRENCY)

    def _probe_one(target: tuple[Any, Any]) -> bool:
        enrollment, lifecycle = target
        nonce = issue_nonce()
        try:
            if production_mode:
                _resolve_endpoint(
                    enrollment.endpoint_url,
                    resolver=resolver,
                    production_mode=True,
                )
                if urlparse(enrollment.endpoint_url).scheme != "https":
                    raise ValueError("production probing requires HTTPS")
                remote_options = {"timeout": TIMEOUT_SECONDS}
                if expected_tier is Tier.CC_GPU:
                    remote_options["max_response_body"] = MAX_EVIDENCE_RESPONSE_BODY
                client = RemoteMiner(
                    enrollment.endpoint_url,
                    enrollment.hotkey,
                    **remote_options,
                )
                if expected_tier is Tier.CC_GPU:
                    with gpu_evidence_slots:
                        evidences = list(client.fetch_evidence_bundle(nonce))
                    channel_evidence = next(
                        item for item in evidences if item.kind is EvidenceKind.TDX
                    )
                else:
                    channel_evidence = client.fetch_evidence(nonce)
                    evidences = [channel_evidence]
            else:
                client = None
                evidences = _request_evidence(
                    enrollment.endpoint_url,
                    enrollment.hotkey,
                    nonce,
                    resolver=resolver,
                    opener=opener,
                    production_mode=False,
                )
            composite = None
            if expected_tier is Tier.CC_GPU:
                from cathedral.gpu import (
                    GpuAttestationError,
                    gpu_error_is_evidence_denial,
                    verify_composite_gpu,
                )

                if production_mode and not gpu_profile.production_ready_for(policy):
                    raise ValueError("production GPU profile expired during probe")
                tdx_components = [item for item in evidences if item.kind is EvidenceKind.TDX]
                gpu_components = [item for item in evidences if item.kind is EvidenceKind.GPU_CC]
                if len(evidences) != 2 or len(tdx_components) != 1 or len(gpu_components) != 1:
                    attested = None
                else:
                    try:
                        composite = verify_composite_gpu(
                            tdx_components[0],
                            gpu_components[0],
                            nonce,
                            policy,
                            gpu_profile,
                            gpu_verifier,
                        )
                        if production_mode and not gpu_profile.production_ready_for(policy):
                            raise ValueError("production GPU profile expired during probe")
                        attested = composite.attested
                    except GpuAttestationError as exc:
                        if not gpu_error_is_evidence_denial(exc):
                            raise
                        LOGGER.info("GPU composite rejected: %s", exc.category)
                        attested = None
            else:
                attested = verify_cc_evidence_bundle(evidences, nonce, policy)
            if attested is None:
                _require_current_policy()
                store.record_verdict(
                    enrollment.hotkey,
                    None,
                    error="verification failed",
                    expected_generation=lifecycle.generation,
                    expected_revision=lifecycle.revision,
                    policy_registry_release=policy.registry_release,
                    policy_registry_digest=policy.registry_digest,
                )
                return False
            else:
                if client is not None:
                    binding = client.confirm_channel_binding(channel_evidence)
                    if (
                        any(item.channel_binding != binding for item in evidences)
                        or attested.assurance is None
                    ):
                        raise ValueError("attested channel binding mismatch")
                    attested = replace(
                        attested,
                        assurance=with_verified_channel(
                            attested.assurance, binding.canonical_bytes()
                        ),
                    )
                pending_gpu_claim = None
                if composite is not None:
                    if production_mode and not gpu_profile.production_ready_for(policy):
                        raise ValueError("production GPU profile expired before admission")
                    try:
                        pending_gpu_claim = gpu_identity_registry.begin_claim(
                            enrollment.hotkey,
                            composite.gpu_component,
                        )
                    except GpuAttestationError as exc:
                        if exc.category != "identity_conflict":
                            raise
                        store.transition_lifecycle(
                            enrollment.hotkey,
                            WorkerLifecycleState.REVOKED,
                            LifecycleReason.IDENTITY_CONFLICT,
                            expected_generation=lifecycle.generation,
                            expected_revision=lifecycle.revision,
                            operator_detail="GPU identity already backs another worker",
                        )
                        return False
                try:
                    _require_current_policy()
                    gpu_commit_authority = {}
                    if composite is not None and production_mode:
                        gpu_commit_authority = {
                            "gpu_profile_valid_from": gpu_profile.registry_valid_from,
                            "gpu_profile_valid_until": gpu_profile.registry_valid_until,
                            "gpu_profile_registry_release": gpu_profile.registry_release,
                            "gpu_profile_registry_digest": gpu_profile.registry_digest,
                        }
                    store.record_verdict(
                        enrollment.hotkey,
                        attested,
                        expected_generation=lifecycle.generation,
                        expected_revision=lifecycle.revision,
                        policy_registry_release=policy.registry_release,
                        policy_registry_digest=policy.registry_digest,
                        **gpu_commit_authority,
                    )
                except BaseException:
                    if pending_gpu_claim is not None:
                        gpu_identity_registry.rollback_claim(pending_gpu_claim)
                    raise
                if pending_gpu_claim is not None:
                    gpu_identity_registry.commit_claim(pending_gpu_claim)
                return True
        except LifecycleError:
            # The endpoint or lifecycle changed while evidence was in flight.
            # The lifecycle CAS rejected the stale result, so do not mutate the
            # replacement generation or schedule a retry against it.
            return False
        except Exception as exc:
            try:
                store.record_probe_failure(
                    enrollment.hotkey,
                    error=type(exc).__name__,
                    expected_generation=lifecycle.generation,
                    expected_revision=lifecycle.revision,
                )
            except LifecycleError:
                return False
            except Exception:
                LOGGER.exception("failed to record probe failure for hotkey %s", enrollment.hotkey)
            return False

    all_succeeded = True
    effective_workers = (
        min(max_workers, MAX_GPU_EVIDENCE_CONCURRENCY)
        if expected_tier is Tier.CC_GPU
        else max_workers
    )
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures = [executor.submit(_probe_one, target) for target in probe_targets]
        for future in as_completed(futures):
            try:
                if not future.result():
                    all_succeeded = False
            except Exception:
                LOGGER.exception("unexpected error in probe worker")
                all_succeeded = False
    return all_succeeded


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Probe enrolled Cathedral miners for TEE evidence")
    parser.add_argument("--db", default="cathedral-enroll.sqlite")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--allow-measurement", action="append", default=[])
    parser.add_argument("--allow-measurements-file")
    parser.add_argument("--min-tcb", type=int, default=0)
    parser.add_argument("--tdx-strict", action="store_true")
    parser.add_argument("--allow-tdx-tcb-status", action="append", default=[])
    parser.add_argument("--allow-tdx-advisory", action="append", default=[])
    parser.add_argument("--policy-registry")
    parser.add_argument("--policy-registry-keys")
    parser.add_argument(
        "--policy-registry-keys-digest",
        help="independently configured sha256 digest of the trusted-key file",
    )
    parser.add_argument("--policy-registry-state")
    parser.add_argument("--policy-registry-min-release", type=int)
    parser.add_argument("--policy-registry-pinned-release", type=int)
    parser.add_argument("--policy-registry-pinned-digest")
    parser.add_argument("--policy-registry-max-age-seconds", type=int, default=86400)
    parser.add_argument(
        "--gpu-profile-id",
        help="active gpu_cc profile id from the verified policy registry",
    )
    parser.add_argument(
        "--gpu-identity-db",
        help="durable pseudonymous GPU identity-claim database",
    )
    parser.add_argument(
        "--gpu-identity-key-file",
        help="owner-only file containing a 32-byte base64 identity key",
    )
    parser.add_argument(
        "--gpu-identity-anchor-file",
        help="external protected monotonic generation anchor",
    )
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
    if args.production_mode and args.policy_registry is None:
        parser.error("--production-mode requires --policy-registry authority")

    store = RegistryStore(args.db)
    gpu_values = (
        args.gpu_profile_id,
        args.gpu_identity_db,
        args.gpu_identity_key_file,
        args.gpu_identity_anchor_file,
    )
    if any(value is not None for value in gpu_values) and any(
        value is None for value in gpu_values
    ):
        parser.error(
            "--gpu-profile-id, --gpu-identity-db, --gpu-identity-key-file, and "
            "--gpu-identity-anchor-file are required together"
        )
    if args.policy_registry is not None:
        if args.allow_measurement or args.allow_measurements_file:
            parser.error("legacy measurement flags and --policy-registry are mutually exclusive")
        for name in ("policy_registry_keys", "policy_registry_state"):
            if getattr(args, name) is None:
                parser.error(f"--{name.replace('_', '-')} is required with --policy-registry")
        from cathedral.cli import _verified_registry_snapshot_and_policy

        registry_refresh_lock = threading.Lock()

        def refresh_registry_authority():
            with registry_refresh_lock:
                return _verified_registry_snapshot_and_policy(
                    args.policy_registry,
                    args.policy_registry_keys,
                    state_path=args.policy_registry_state,
                    minimum_release=args.policy_registry_min_release,
                    max_age_seconds=args.policy_registry_max_age_seconds,
                    production_mode=args.production_mode,
                    trusted_keys_digest=args.policy_registry_keys_digest,
                    pinned_release=args.policy_registry_pinned_release,
                    pinned_digest=args.policy_registry_pinned_digest,
                )

        policy, policy_snapshot = refresh_registry_authority()
    else:
        policy = policy_from_args(args)
        policy_snapshot = None
        refresh_registry_authority = None
    gpu_profile = None
    gpu_verifier = None
    gpu_identity_registry = None
    expected_tier = Tier.CC_CPU_TDX
    if args.gpu_profile_id is not None:
        if policy_snapshot is None:
            parser.error("GPU probing requires --policy-registry authority")
        from cathedral.cli import _load_gpu_identity_key
        from cathedral.gpu import (
            GpuIdentityRegistry,
            gpu_profile_from_registry,
            gpu_verifier_from_env,
        )

        gpu_profile = gpu_profile_from_registry(policy_snapshot, args.gpu_profile_id)
        gpu_verifier = gpu_verifier_from_env(production_mode=args.production_mode)
        gpu_identity_registry = GpuIdentityRegistry(
            args.gpu_identity_db,
            identity_digest_key=_load_gpu_identity_key(
                args.gpu_identity_key_file,
                production_mode=args.production_mode,
            ),
            production_mode=args.production_mode,
            generation_anchor_path=args.gpu_identity_anchor_file,
        )
        expected_tier = Tier.CC_GPU
    while True:
        try:
            if args.policy_registry is not None:
                assert refresh_registry_authority is not None
                policy, policy_snapshot = refresh_registry_authority()
                if args.gpu_profile_id is not None:
                    gpu_profile = gpu_profile_from_registry(policy_snapshot, args.gpu_profile_id)
            all_succeeded = probe_once(
                store,
                policy,
                max_workers=args.workers,
                production_mode=args.production_mode,
                policy_refresher=(
                    (lambda: refresh_registry_authority()[0])
                    if refresh_registry_authority is not None
                    else None
                ),
                gpu_profile=gpu_profile,
                gpu_verifier=gpu_verifier,
                gpu_identity_registry=gpu_identity_registry,
                expected_tier=expected_tier,
            )
            if args.once and not all_succeeded:
                raise RuntimeError("one-shot probe did not verify every due target")
        except Exception:
            LOGGER.exception("probe pass failed")
            if args.once:
                raise
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
