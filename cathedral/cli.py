"""Cathedral operator CLI (docs/DESIGN.md §7, §10).

Thin argparse front-end over the in-process control plane (cathedral.api),
the SAT lane (cathedral.lanes.sat), and the shared Policy check
(cathedral.common). ``work submit`` and ``work status`` use the runtime's
durable SQLite ledger so customer work can be atomically leased to admitted
CPU workers instead of living in a disconnected local file.

Every subcommand is a plain, importable function taking parsed args and
returning an int exit code -- callers (tests, scripts) never need to shell
out.

    python -m cathedral.cli census
    python -m cathedral.cli verify-quote --measurement M --allowed-measurement M --tcb 3 --min-tcb 1
    python -m cathedral.cli work submit --ledger-db runtime.sqlite --customer-id demo --n-vars 3 --clauses '[[1, 2, -3]]'
    python -m cathedral.cli work status --ledger-db runtime.sqlite
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from cathedral import census as census_mod
from cathedral.attest import collect_tdx_gpu
from cathedral.assurance import AssuranceDimension
from cathedral.channel import ChannelBindingError, tls_spki_binding
from cathedral.common import ChannelBinding, ChannelBindingType, Policy, Tier
from cathedral.enroll import RegistryStore
from cathedral.gpu import (
    GpuIdentityRegistry,
    gpu_profile_from_registry,
    gpu_verifier_from_env,
)
from cathedral.lanes.sat import SatLane, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.ledger import Ledger
from cathedral.poster import Poster
from cathedral.policy_registry import (
    MAX_REGISTRY_BYTES,
    PolicyRegistryError,
    PolicyRegistrySnapshot,
    PolicyRegistryState,
    parse_registry_json,
    verify_registry,
)
from cathedral.receipt import (
    MAX_RECEIPT_BYTES,
    ReceiptError,
    ReceiptIssuer,
    parse_receipt_json,
    verify_receipt,
)
from cathedral.runtime import (
    ConfidentialRuntime,
    EpochRun,
    MAX_BEARER_TOKEN_LENGTH,
    MinerOutcome,
    MinerTarget,
    RuntimeConfig,
)
from cathedral.score_class import export_score_class_report
from cathedral.worker import WorkerServer

DEFAULT_PUBLISHER_BEARER_ENV = "CATHEDRAL_PUBLISHER_BEARER_TOKEN"
DEFAULT_PUBLISHER_HMAC_ENV = "CATHEDRAL_PUBLISHER_HMAC_SECRET"
DEFAULT_WORKER_BEARER_ENV = "CATHEDRAL_WORKER_BEARER_TOKEN"


# --------------------------------------------------------------------------
# pretty output helpers: human-readable operator logs for run-epoch and
# retry-publish.  JSON is still the default; --pretty opts in.
# --------------------------------------------------------------------------


def _utc_ts() -> str:
    """Current UTC timestamp in compact ISO format for operator logs."""
    return datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _abbrev(s: str | None, prefix: int = 5, suffix: int = 4) -> str:
    """Abbreviate a long identifier (hotkey, challenge ID) for single-line display."""
    if not s:
        return "-"
    if len(s) <= prefix + suffix + 2:
        return s
    return f"{s[:prefix]}..{s[-suffix:]}"


# Patterns that identify a credential value inside an error string.
# Conservative: require an explicit keyword followed by = or : and a
# non-whitespace token.  The key name is preserved; only the value is
# replaced.  Redaction runs before truncation so no partial secret can
# survive at the length boundary.
_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Authorization: Bearer <token>  (HTTP header echoed in error text)
    re.compile(r"(Authorization\s*:\s*Bearer\s+)\S+", re.IGNORECASE),
    # bearer=, token=, secret=, hmac=, api_key=, api-key=, apikey=
    re.compile(
        r"((?:bearer|token|secret|hmac|api[-_]?key)\s*[=:]\s*)\S+",
        re.IGNORECASE,
    ),
)
_REDACT_REPLACEMENT = r"\g<1>[REDACTED]"


def _sanitize_error(err: str | None, maxlen: int = 100) -> str:
    """Flatten, redact credential patterns, and truncate an error string.

    Redaction targets obvious credential assignments embedded in upstream
    error messages:

    * ``Authorization: Bearer <token>`` (HTTP header echoed verbatim)
    * ``bearer=``, ``token=``, ``secret=``, ``hmac=``, ``api_key=``,
      ``api-key=`` assignments (``=`` or ``:`` separator, case-insensitive)

    Non-secret text is preserved.  Redaction runs before truncation so a
    partial credential cannot survive at the length boundary.
    """
    if not err:
        return ""
    # 1. Flatten to a single line.
    flat = err.replace("\n", " ").replace("\r", " ").strip()
    # 2. Redact credential-shaped patterns.
    for pattern in _REDACT_PATTERNS:
        flat = pattern.sub(_REDACT_REPLACEMENT, flat)
    # 3. Truncate.
    return flat[:maxlen]


def _pretty_outcome_indicator(outcome: MinerOutcome) -> str:
    """Return a fixed-width 4-char status indicator: OK, ZERO, or FAIL."""
    if outcome.admitted and outcome.score > 0.0:
        return "OK  "
    if outcome.admitted:
        return "ZERO"
    return "FAIL"


def _format_run_pretty(run: EpochRun, *, out: object = None) -> None:
    """Write a concise ASCII epoch summary to *out* (default: sys.stdout).

    One lifecycle header, one line per worker, one summary footer::

        [TIMESTAMP] EPOCH START  source=N  ep=N
        [TIMESTAMP] OK    5Ctob..awK  ep=7/1  admit=Y  work=verified
                    wu=20.00  score=1.000  pub=NO  ch=ababab..bababa
        [TIMESTAMP] ZERO  5Zero..ero  ep=7/1  admit=Y  work=sat_failed
                    wu=0.00  score=0.000  pub=NO  ch=cdcdcd..dcdcdc
                    err=invalid SAT certificate
        [TIMESTAMP] FAIL  5Fail..ail  ep=7/1  admit=N  work=attestation_failed
                    wu=0.00  score=0.000  pub=NO  err=worker returned HTTP 401
        [TIMESTAMP] EPOCH END  ep=7/1  status=complete  published=NO
                    ok=1  zeros=1  fail=1
    """
    if out is None:
        out = sys.stdout

    pub_str = "YES" if run.published else "NO"

    print(
        f"[{_utc_ts()}] EPOCH START  source={run.source_epoch}  ep={run.epoch_id}",
        file=out,
    )

    ok_count = zero_count = fail_count = 0
    for outcome in run.outcomes:
        ind = _pretty_outcome_indicator(outcome)
        if ind == "OK  ":
            ok_count += 1
        elif ind == "ZERO":
            zero_count += 1
        else:
            fail_count += 1

        hotkey_str = _abbrev(outcome.hotkey, prefix=5, suffix=4)
        ch_str = _abbrev(outcome.challenge_id, prefix=6, suffix=6)
        admit_str = "Y" if outcome.admitted else "N"
        err_part = f"  err={_sanitize_error(outcome.error)}" if outcome.error else ""

        print(
            f"[{_utc_ts()}] {ind}  {hotkey_str:<14}"
            f"  ep={run.source_epoch}/{run.epoch_id}"
            f"  admit={admit_str}"
            f"  work={outcome.status:<22}"
            f"  wu={outcome.work_units:>8.2f}"
            f"  score={outcome.score:.3f}"
            f"  pub={pub_str}"
            f"  ch={ch_str}"
            f"{err_part}",
            file=out,
        )
        if outcome.assurance is not None:
            claim_summary = " ".join(
                f"{dimension.value[0].upper()}={outcome.assurance.claim(dimension).status.value}"
                for dimension in AssuranceDimension
            )
            print(f"            assurance {claim_summary}", file=out)

    status_flag = "  !! EPOCH FAILED" if run.status not in {"complete", "published"} else ""
    print(
        f"[{_utc_ts()}] EPOCH END"
        f"  ep={run.source_epoch}/{run.epoch_id}"
        f"  status={run.status}{status_flag}"
        f"  published={pub_str}"
        f"  workers={len(run.outcomes)}"
        f"  ok={ok_count}  zeros={zero_count}  fail={fail_count}",
        file=out,
    )


def _format_publish_pretty(epoch_id: int, ack: dict[str, object], *, out: object = None) -> None:
    """Write a concise human-readable publish acknowledgement to *out*."""
    if out is None:
        out = sys.stdout
    ack_status = ack.get("status", "?")
    print(
        f"[{_utc_ts()}] PUBLISH  epoch={epoch_id}  ok  ack={ack_status}",
        file=out,
    )


def _item_to_dict(item: SatWorkItem) -> dict:
    return {
        "n_vars": item.instance.n_vars,
        "clauses": item.instance.clauses,
        "seed": item.seed,
        "challenge_id": item.challenge_id,
    }


def _dict_to_item(d: dict) -> SatWorkItem:
    instance = SatInstance(n_vars=d["n_vars"], clauses=d["clauses"])
    # Legacy queue entries may lack challenge_id; recompute and validate.
    stored_id = d.get("challenge_id")
    computed_id = _compute_challenge_id(instance, d["seed"])
    if stored_id is not None and stored_id != computed_id:
        raise ValueError(
            f"persisted challenge_id {stored_id} does not match "
            f"recomputed {computed_id} for seed={d['seed']}"
        )
    return SatWorkItem(instance=instance, seed=d["seed"], challenge_id=computed_id)


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------


def cmd_census(args: argparse.Namespace) -> int:
    return census_mod.main()


def cmd_verify_quote(args: argparse.Namespace) -> int:
    policy = Policy(allowed_measurements=set(args.allowed_measurement), min_tcb=args.min_tcb)
    ok = args.measurement in policy.allowed_measurements and args.tcb >= policy.min_tcb
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def cmd_work_submit(args: argparse.Namespace) -> int:
    if args.clauses is not None:
        clauses = json.loads(args.clauses)
        instance = SatInstance(n_vars=args.n_vars, clauses=clauses)
        seed = args.seed if args.seed is not None else 0
        challenge_id = _compute_challenge_id(instance, seed)
        item = SatWorkItem(instance=instance, seed=seed, challenge_id=challenge_id)
    else:
        # No explicit job given: backfill one canonical instance to submit.
        dispatched = SatLane().dispatch("cli-submit", budget=1)
        assert isinstance(dispatched, SatWorkItem)
        item = dispatched

    with Ledger(args.ledger_db) as ledger:
        job = ledger.enqueue_customer_job(
            item,
            customer_id=getattr(args, "customer_id", "operator"),
            idempotency_key=getattr(args, "idempotency_key", None),
        )
        queued = ledger.customer_job_counts()["queued"]
    print(f"submitted {job.job_id} (n_vars={item.instance.n_vars}, seed={item.seed}); queued={queued}")
    return 0


def cmd_work_status(args: argparse.Namespace) -> int:
    with Ledger(args.ledger_db) as ledger:
        job_id = getattr(args, "job_id", None)
        if job_id is not None:
            job = ledger.customer_job(job_id)
            print(
                json.dumps(
                    {
                        "job_id": job.job_id,
                        "customer_id": job.customer_id,
                        "status": job.status,
                        "attempt_count": job.attempt_count,
                        "lease_owner": job.lease_owner,
                        "lease_epoch_id": job.lease_epoch_id,
                        "result": dict(job.result) if job.result is not None else None,
                        "last_error": (
                            _sanitize_error(job.last_error, maxlen=300)
                            if job.last_error is not None
                            else None
                        ),
                    },
                    sort_keys=True,
                )
            )
            return 0
        counts = ledger.customer_job_counts()
    print(json.dumps({"customer_jobs": dict(counts)}, sort_keys=True))
    return 0


def cmd_work_prune(args: argparse.Namespace) -> int:
    if not getattr(args, "confirm", False):
        raise ValueError("work prune requires --confirm")
    try:
        before = datetime.datetime.fromisoformat(args.resolved_before.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise ValueError("--resolved-before must be a UTC ISO-8601 timestamp") from None
    if before.tzinfo is None or before.utcoffset() != datetime.timedelta(0):
        raise ValueError("--resolved-before must be a UTC ISO-8601 timestamp")
    with Ledger(args.ledger_db) as ledger:
        removed = ledger.prune_customer_jobs(
            before,
            limit=args.limit,
            customer_id=getattr(args, "customer_id", None),
        )
    print(json.dumps({"pruned_customer_jobs": removed}, sort_keys=True))
    return 0


def _load_json(path: str, description: str) -> object:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load {description} file") from exc


def _load_policy(path: str) -> Policy:
    raw = _load_json(path, "measurements")
    if isinstance(raw, list):
        measurements = raw
        min_tcb = 0
        tdx_strict = False
        tdx_allowed_tcb_statuses = ["UpToDate"]
        tdx_allowed_advisories: list[str] = []
    elif isinstance(raw, dict):
        measurements = raw.get("allowed_measurements")
        min_tcb = raw.get("min_tcb", 0)
        tdx_strict = raw.get("tdx_strict", False)
        tdx_allowed_tcb_statuses = raw.get("tdx_allowed_tcb_statuses", ["UpToDate"])
        tdx_allowed_advisories = raw.get("tdx_allowed_advisories", [])
    else:
        raise ValueError("measurements file must be a JSON array or object")
    if not isinstance(measurements, list) or any(
        not isinstance(value, str) or not value for value in measurements
    ):
        raise ValueError("allowed_measurements must be a list of nonempty strings")
    if isinstance(min_tcb, bool) or not isinstance(min_tcb, int) or min_tcb < 0:
        raise ValueError("min_tcb must be a nonnegative integer")
    if not isinstance(tdx_strict, bool):
        raise ValueError("tdx_strict must be a boolean")
    for name, values in (
        ("tdx_allowed_tcb_statuses", tdx_allowed_tcb_statuses),
        ("tdx_allowed_advisories", tdx_allowed_advisories),
    ):
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value for value in values
        ):
            raise ValueError(f"{name} must be a list of nonempty strings")
    return Policy(
        allowed_measurements=set(measurements),
        min_tcb=min_tcb,
        tdx_strict=tdx_strict,
        tdx_allowed_tcb_statuses=set(tdx_allowed_tcb_statuses),
        tdx_allowed_advisories=set(tdx_allowed_advisories),
    )


def _read_bounded_registry_file(path: str, label: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_REGISTRY_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"unable to load {label}") from exc
    if len(data) > MAX_REGISTRY_BYTES:
        raise ValueError(f"{label} exceeds the maximum encoded size")
    return data


def _load_registry_keys(
    path: str,
    *,
    production_mode: bool = False,
    pinned_digest: str | None = None,
) -> dict[str, bytes]:
    encoded = _read_bounded_registry_file(path, "policy registry key file")
    if production_mode and pinned_digest is None:
        raise ValueError("production policy registry keys require a pinned digest")
    if pinned_digest is not None:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", pinned_digest) is None:
            raise ValueError("policy registry key digest is invalid")
        actual_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(actual_digest, pinned_digest):
            raise ValueError("policy registry key digest does not match")
    raw = parse_registry_json(encoded)
    keys: dict[str, bytes] = {}
    try:
        for key_id, encoded in raw.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(encoded, str):
                raise ValueError
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32:
                raise ValueError
            keys[key_id] = key
    except (binascii.Error, ValueError):
        raise ValueError("policy registry keys must be 32-byte base64 values") from None
    if not keys:
        raise ValueError("policy registry key file cannot be empty")
    return keys


def _verified_registry_policy(
    registry_path: str,
    keys_path: str,
    *,
    state_path: str,
    minimum_release: int | None,
    max_age_seconds: int,
    production_mode: bool,
    trusted_keys_digest: str | None = None,
    pinned_release: int | None = None,
    pinned_digest: str | None = None,
) -> Policy:
    policy, _snapshot = _verified_registry_snapshot_and_policy(
        registry_path,
        keys_path,
        state_path=state_path,
        minimum_release=minimum_release,
        max_age_seconds=max_age_seconds,
        production_mode=production_mode,
        trusted_keys_digest=trusted_keys_digest,
        pinned_release=pinned_release,
        pinned_digest=pinned_digest,
    )
    return policy


def _verified_registry_snapshot_and_policy(
    registry_path: str,
    keys_path: str,
    *,
    state_path: str,
    minimum_release: int | None,
    max_age_seconds: int,
    production_mode: bool,
    trusted_keys_digest: str | None = None,
    pinned_release: int | None = None,
    pinned_digest: str | None = None,
) -> tuple[Policy, PolicyRegistrySnapshot]:
    data = _read_bounded_registry_file(registry_path, "policy registry")
    snapshot = verify_registry(
        data,
        _load_registry_keys(
            keys_path,
            production_mode=production_mode,
            pinned_digest=trusted_keys_digest,
        ),
        max_age_seconds=max_age_seconds,
    )
    # Prove the signed snapshot can produce a usable CPU admission policy
    # before advancing the durable high-water mark.
    policy = snapshot.to_policy(max_age_seconds=max_age_seconds)
    state = PolicyRegistryState(
        state_path,
        production_mode=production_mode,
        minimum_release=minimum_release,
        pinned_release=pinned_release,
        pinned_digest=pinned_digest,
    )
    state.accept(snapshot)
    return policy, snapshot


def _read_bounded_receipt_file(path: str, label: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_RECEIPT_BYTES + 1)
    except OSError as exc:
        raise ReceiptError("schema", f"unable to load {label}") from exc
    if len(data) > MAX_RECEIPT_BYTES:
        raise ReceiptError("schema", f"{label} exceeds the maximum encoded size")
    return data


def _load_private_seed(
    path: str,
    *,
    production_mode: bool,
    label: str,
) -> bytes:
    target = Path(path)
    try:
        before = target.lstat()
    except OSError as exc:
        raise ValueError(f"unable to load {label}") from exc
    if not stat.S_ISREG(before.st_mode) or target.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ValueError(f"unable to load {label}") from exc
    try:
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise ValueError(f"{label} must be a stable regular non-symlink file")
            if production_mode and metadata.st_mode & 0o077:
                raise ValueError(f"production {label} must not be group/world accessible")
            if production_mode and hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError(f"production {label} must be owned by the runtime user")
            raw = os.read(descriptor, 257)
        except OSError as exc:
            raise ValueError(f"unable to load {label}") from exc
    finally:
        os.close(descriptor)
    if len(raw) > 256:
        raise ValueError(f"{label} must be a 32-byte base64 seed")
    try:
        seed = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be a 32-byte base64 seed") from exc
    if len(seed) != 32:
        raise ValueError(f"{label} must be a 32-byte base64 seed")
    return seed


def _load_receipt_private_seed(path: str, *, production_mode: bool) -> bytes:
    return _load_private_seed(
        path,
        production_mode=production_mode,
        label="receipt signing key",
    )


def _load_gpu_identity_key(path: str, *, production_mode: bool) -> bytes:
    return _load_private_seed(
        path,
        production_mode=production_mode,
        label="GPU identity key",
    )


def cmd_policy_registry_verify(args: argparse.Namespace) -> int:
    historical_at = None
    historical_raw = getattr(args, "historical_at", None)
    if historical_raw is not None:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", historical_raw) is None:
            raise ValueError("--historical-at must be canonical UTC time")
        try:
            historical_at = datetime.datetime.strptime(
                historical_raw, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=datetime.UTC)
        except ValueError:
            raise ValueError("--historical-at must be canonical UTC time") from None
    registry_bytes = _read_bounded_registry_file(args.registry, "policy registry")
    snapshot = verify_registry(
        registry_bytes,
        _load_registry_keys(args.trusted_keys),
        max_age_seconds=args.max_age_seconds,
        historical_at=historical_at,
    )
    print(
        json.dumps(
            {
                "release": snapshot.release,
                "digest": snapshot.digest,
                "signing_key_id": snapshot.signing_key_id,
                "profiles": [
                    {"id": profile.profile_id, "kind": profile.kind, "status": profile.status}
                    for profile in snapshot.profiles
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_receipt_verify(args: argparse.Namespace) -> int:
    try:
        receipt_bytes = _read_bounded_receipt_file(args.receipt, "assurance receipt")
        preview = parse_receipt_json(receipt_bytes)
        issued_raw = preview.get("issued_at")
        if (
            not isinstance(issued_raw, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", issued_raw) is None
        ):
            raise ReceiptError("schema", "receipt issued_at is invalid")
        try:
            issued_at = datetime.datetime.strptime(issued_raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=datetime.UTC
            )
        except ValueError as exc:
            raise ReceiptError("schema", "receipt issued_at is invalid") from exc
        policy_registry = verify_registry(
            _read_bounded_registry_file(args.policy_registry, "policy registry"),
            _load_registry_keys(args.trusted_keys),
            historical_at=issued_at,
        )
        key_registry = policy_registry
        if getattr(args, "key_registry", None) is not None:
            key_registry = verify_registry(
                _read_bounded_registry_file(args.key_registry, "receipt key registry"),
                _load_registry_keys(args.key_registry_trusted_keys or args.trusted_keys),
                max_age_seconds=args.key_registry_max_age_seconds,
            )
        verified = verify_receipt(
            receipt_bytes,
            policy_registry,
            key_registry=key_registry,
        )
    except ReceiptError as exc:
        print(
            json.dumps(
                {"valid": False, "category": exc.category, "error": str(exc)},
                sort_keys=True,
            )
        )
        return 1
    except (PolicyRegistryError, ValueError) as exc:
        print(
            json.dumps(
                {"valid": False, "category": "policy_registry", "error": str(exc)},
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "valid": True,
                "receipt_id": verified.receipt_id,
                "receipt_digest": verified.receipt_digest,
                "policy_registry_release": policy_registry.release,
                "key_registry_release": key_registry.release,
            },
            sort_keys=True,
        )
    )
    return 0


def _load_tokens(path: str | None, *, production_mode: bool = False) -> dict[str, str]:
    if path is None:
        return {}
    if production_mode and os.name == "posix":
        raw = _load_production_tokens(path)
    else:
        raw = _load_json(path, "token mapping")
    if not isinstance(raw, dict) or any(
        not isinstance(hotkey, str) or not hotkey or not _valid_bearer_token(token)
        for hotkey, token in raw.items()
    ):
        raise ValueError("token mapping must contain bounded bearer tokens")
    return dict(raw)


def _load_production_tokens(path: str) -> object:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor: int | None = os.open(path, flags)
    except OSError as exc:
        raise ValueError("unable to securely open token mapping file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("production token mapping must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("production token mapping permissions must be owner-only")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("production token mapping must be owned by the current user")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = None
            try:
                return json.load(handle)
            except json.JSONDecodeError as exc:
                raise ValueError("unable to load token mapping file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _valid_bearer_token(token: object) -> bool:
    return (
        isinstance(token, str)
        and 0 < len(token) <= MAX_BEARER_TOKEN_LENGTH
        and all(0x21 <= ord(character) <= 0x7E for character in token)
    )


def _publisher_from_args(args: argparse.Namespace) -> Poster | None:
    endpoint = getattr(args, "publisher_endpoint", None)
    if endpoint is None:
        return None
    bearer_env = args.publisher_bearer_env
    hmac_env = args.publisher_hmac_env
    bearer = os.environ.get(bearer_env)
    secret = os.environ.get(hmac_env)
    if not bearer or not secret:
        raise ValueError(f"publisher credentials must be set in {bearer_env} and {hmac_env}")
    return Poster(
        endpoint,
        bearer,
        secret,
        network=getattr(args, "score_network", None),
        netuid=getattr(args, "score_netuid", None),
    )


def _build_runtime(
    args: argparse.Namespace,
    *,
    require_policy: bool = False,
    require_report_audience: bool = False,
) -> tuple[ConfidentialRuntime, Ledger, dict[str, str]]:
    development = getattr(args, "development", False)
    gpu_profile_id = getattr(args, "gpu_profile_id", None)
    gpu_identity_db = getattr(args, "gpu_identity_db", None)
    gpu_identity_key_file = getattr(args, "gpu_identity_key_file", None)
    gpu_identity_anchor_file = getattr(args, "gpu_identity_anchor_file", None)
    gpu_values = (
        gpu_profile_id,
        gpu_identity_db,
        gpu_identity_key_file,
        gpu_identity_anchor_file,
    )
    if any(item is not None for item in gpu_values) and any(item is None for item in gpu_values):
        raise ValueError(
            "--gpu-profile-id, --gpu-identity-db, --gpu-identity-key-file, and "
            "--gpu-identity-anchor-file are required together"
        )
    config = RuntimeConfig(
        miner_timeout_seconds=getattr(args, "miner_timeout_seconds", 10.0),
        miner_attempts=getattr(args, "miner_attempts", 2),
        max_workers=getattr(args, "max_workers", 8),
        production_mode=not development,
        allow_insecure_http_for_tests=development,
        reattestation_failures_before_failed=getattr(
            args, "reattestation_failures_before_failed", 3
        ),
        reattestation_retry_base_seconds=getattr(args, "reattestation_retry_base_seconds", 5),
        reattestation_retry_maximum_seconds=getattr(
            args, "reattestation_retry_maximum_seconds", 300
        ),
        reattestation_retry_jitter_seconds=getattr(args, "reattestation_retry_jitter_seconds", 5),
        customer_job_lease_seconds=getattr(args, "customer_job_lease_seconds", 120),
        customer_job_max_attempts=getattr(args, "customer_job_max_attempts", 3),
        expected_tier=Tier.CC_GPU if gpu_profile_id is not None else Tier.CC_CPU_TDX,
        admission_enabled=require_policy,
        score_network=getattr(args, "score_network", None),
        score_netuid=getattr(args, "score_netuid", None),
    )
    if require_report_audience and config.production_mode and config.score_network is None:
        raise ValueError("production score reports require --score-network and --score-netuid")
    tokens = _load_tokens(
        getattr(args, "tokens_file", None),
        production_mode=config.production_mode,
    )
    measurements_file = getattr(args, "measurements_file", None)
    policy_registry = getattr(args, "policy_registry", None)
    policy_snapshot: PolicyRegistrySnapshot | None = None
    policy_refresher = None
    if measurements_file and policy_registry:
        raise ValueError("--measurements-file and --policy-registry are mutually exclusive")
    if policy_registry is not None:
        for name in ("policy_registry_keys", "policy_registry_state"):
            if not getattr(args, name, None):
                raise ValueError(f"--{name.replace('_', '-')} is required with --policy-registry")
        policy, policy_snapshot = _verified_registry_snapshot_and_policy(
            policy_registry,
            args.policy_registry_keys,
            state_path=args.policy_registry_state,
            minimum_release=args.policy_registry_min_release,
            max_age_seconds=args.policy_registry_max_age_seconds,
            production_mode=config.production_mode,
            trusted_keys_digest=getattr(args, "policy_registry_keys_digest", None),
            pinned_release=getattr(args, "policy_registry_pinned_release", None),
            pinned_digest=getattr(args, "policy_registry_pinned_digest", None),
        )
        if config.production_mode:

            def refresh_policy() -> Policy:
                refreshed, _snapshot = _verified_registry_snapshot_and_policy(
                    policy_registry,
                    args.policy_registry_keys,
                    state_path=args.policy_registry_state,
                    minimum_release=args.policy_registry_min_release,
                    max_age_seconds=args.policy_registry_max_age_seconds,
                    production_mode=True,
                    trusted_keys_digest=getattr(args, "policy_registry_keys_digest", None),
                    pinned_release=getattr(args, "policy_registry_pinned_release", None),
                    pinned_digest=getattr(args, "policy_registry_pinned_digest", None),
                )
                return refreshed

            policy_refresher = refresh_policy
    elif measurements_file:
        if config.production_mode:
            raise ValueError(
                "production admission requires --policy-registry; "
                "--measurements-file is development-only"
            )
        policy = _load_policy(measurements_file)
    elif require_policy:
        raise ValueError("one of --measurements-file or --policy-registry is required")
    else:
        # Recovery/status commands do not admit miners or start epochs. Their
        # runtime methods operate only on already-frozen ledger state, so they
        # intentionally need no current admission policy.
        policy = Policy()
    if require_policy and config.production_mode and not policy.production_ready_for_tdx:
        raise ValueError(
            "production admission requires strict signed CPU policy registry authority"
        )
    receipt_key_id = getattr(args, "receipt_signing_key_id", None)
    receipt_key_file = getattr(args, "receipt_signing_key_file", None)
    if (receipt_key_id is None) != (receipt_key_file is None):
        raise ValueError(
            "--receipt-signing-key-id and --receipt-signing-key-file are required together"
        )
    receipt_issuer = None
    if receipt_key_id is not None:
        if policy_snapshot is None:
            raise ValueError("receipt issuance requires --policy-registry authority")
        receipt_issuer = ReceiptIssuer(
            policy_snapshot,
            receipt_key_id,
            _load_receipt_private_seed(
                receipt_key_file,
                production_mode=config.production_mode,
            ),
        )
    gpu_profile = None
    gpu_verifier = None
    gpu_identity_registry = None
    if gpu_profile_id is not None:
        if policy_snapshot is None:
            raise ValueError("GPU runtime requires --policy-registry authority")
        if config.production_mode and gpu_identity_db == ":memory:":
            raise ValueError("production GPU identity registry must be durable")
        gpu_profile = gpu_profile_from_registry(policy_snapshot, gpu_profile_id)
        if not gpu_profile.production_ready:
            raise ValueError("GPU profile is not production ready")
        gpu_verifier = gpu_verifier_from_env(production_mode=config.production_mode)
        gpu_identity_registry = GpuIdentityRegistry(
            gpu_identity_db,
            identity_digest_key=_load_gpu_identity_key(
                gpu_identity_key_file,
                production_mode=config.production_mode,
            ),
            production_mode=config.production_mode,
            generation_anchor_path=gpu_identity_anchor_file,
        )
    ledger = Ledger(args.ledger_db)
    runtime = ConfidentialRuntime(
        RegistryStore(getattr(args, "registry_db", ":memory:")),
        ledger,
        policy,
        _publisher_from_args(args),
        token_provider=tokens.get,
        policy_refresher=policy_refresher,
        config=config,
        receipt_issuer=receipt_issuer,
        gpu_profile=gpu_profile,
        gpu_verifier=gpu_verifier,
        gpu_identity_registry=gpu_identity_registry,
    )
    return runtime, ledger, tokens


def _target(args: argparse.Namespace, tokens: dict[str, str]) -> MinerTarget:
    return MinerTarget(args.canary_hotkey, args.canary_endpoint, tokens.get(args.canary_hotkey))


def _outcome_json(outcome: MinerOutcome) -> dict[str, object]:
    # Miner/upstream error text may echo request context (headers, URLs) that
    # embeds a credential; sanitize it here too so the default JSON path gets
    # the same redaction as --pretty, not just a narrower one applied later.
    return {
        "hotkey": outcome.hotkey,
        "endpoint_url": outcome.endpoint_url,
        "status": outcome.status,
        "verified": outcome.status == "attestation_verified" or outcome.admitted,
        "admitted": outcome.admitted,
        "challenge_id": outcome.challenge_id,
        "work_units": outcome.work_units,
        "score": outcome.score,
        "error": _sanitize_error(outcome.error, maxlen=300) if outcome.error else None,
        "error_category": outcome.error_category,
        "assurance": outcome.assurance.to_dict() if outcome.assurance else None,
        "component_audit": (
            _audit_json_value(outcome.component_audit)
            if outcome.component_audit is not None
            else None
        ),
    }


def _audit_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _audit_json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_audit_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("component audit contains an unsupported value")


def _run_json(run: EpochRun) -> dict[str, object]:
    return {
        "epoch_id": run.epoch_id,
        "source_epoch": run.source_epoch,
        "status": run.status,
        "published": run.published,
        "scores": dict(run.scores),
        "outcomes": [_outcome_json(outcome) for outcome in run.outcomes],
    }


def cmd_worker_serve(args: argparse.Namespace) -> int:
    tls_certificate = getattr(args, "tls_certificate", None)
    tls_private_key = getattr(args, "tls_private_key", None)
    if (tls_certificate is None) != (tls_private_key is None):
        raise ValueError("worker TLS certificate and private key must be supplied together")
    tls_enabled = tls_certificate is not None
    try:
        is_loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        is_loopback = args.host == "localhost"
    if not is_loopback and not tls_enabled and not args.development_allow_non_loopback:
        raise ValueError("plain worker HTTP must bind loopback unless development mode is explicit")
    if getattr(args, "development_no_auth", False):
        token = None
    else:
        bearer_env = getattr(args, "bearer_token_env", DEFAULT_WORKER_BEARER_ENV)
        if not isinstance(bearer_env, str) or not bearer_env:
            raise ValueError("worker bearer environment variable name is required")
        token = os.environ.get(bearer_env)
        if not _valid_bearer_token(token):
            raise ValueError(f"worker bearer token must be set in {bearer_env}")
    binding_type = getattr(args, "channel_binding_type", None)
    binding_digest = getattr(args, "channel_binding_digest", None)
    if (binding_type is None) != (binding_digest is None):
        raise ValueError("worker channel binding type and digest must be supplied together")
    channel_binding = None
    if binding_type is not None:
        try:
            if re.fullmatch(r"[0-9a-f]{64}", binding_digest) is None:
                raise ValueError
            digest = bytes.fromhex(binding_digest)
            channel_binding = ChannelBinding(ChannelBindingType(binding_type), digest)
        except (TypeError, ValueError):
            raise ValueError("worker channel binding is invalid") from None
    tls_context = None
    if tls_enabled:
        key_path = Path(tls_private_key)
        try:
            key_stat = key_path.lstat()
        except OSError as exc:
            raise ValueError("worker TLS private key is not readable") from exc
        if (
            not stat.S_ISREG(key_stat.st_mode)
            or stat.S_ISLNK(key_stat.st_mode)
            or key_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ValueError("worker TLS private key must be a regular owner-only file")
        certificate_path = Path(tls_certificate)
        try:
            certificate_pem = certificate_path.read_text(encoding="ascii")
            match = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                certificate_pem,
                flags=re.DOTALL,
            )
            if match is None:
                raise ValueError
            certificate_der = ssl.PEM_cert_to_DER_cert(match.group(0))
            certificate_binding = tls_spki_binding(certificate_der)
        except (OSError, UnicodeError, ValueError, ChannelBindingError) as exc:
            raise ValueError("worker TLS certificate is invalid") from exc
        if channel_binding is not None and channel_binding != certificate_binding:
            raise ValueError("worker channel binding does not match TLS certificate")
        channel_binding = certificate_binding
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            tls_context.load_cert_chain(
                certfile=str(certificate_path), keyfile=str(key_path)
            )
        except (OSError, ssl.SSLError) as exc:
            raise ValueError("worker TLS certificate or private key could not be loaded") from exc
    if not getattr(args, "development_no_auth", False) and channel_binding is None:
        raise ValueError("production worker requires a configured channel binding")
    allow_customer_sat = getattr(args, "allow_customer_sat", False)
    if allow_customer_sat and (token is None or channel_binding is None):
        raise ValueError("customer SAT requires bearer authentication and channel binding")
    if allow_customer_sat and getattr(args, "development_allow_non_loopback", False):
        raise ValueError("customer SAT cannot use the development non-loopback HTTP bind")
    if allow_customer_sat and getattr(args, "gpu_composite", False):
        raise ValueError("customer SAT is available only on the CPU worker path")
    with WorkerServer(
        args.host,
        args.port,
        configured_hotkey=args.hotkey,
        bearer_token=token,
        channel_binding=channel_binding,
        tls_context=tls_context,
        evidence_collector=(collect_tdx_gpu if getattr(args, "gpu_composite", False) else None),
        allow_noncanonical_sat=allow_customer_sat,
        allow_non_loopback_for_development=args.development_allow_non_loopback,
    ) as server:
        print(
            json.dumps(
                {
                    "host": server.host,
                    "port": server.port,
                    "hotkey": args.hotkey,
                    "tls": tls_context is not None,
                }
            )
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


def cmd_runtime_canary(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(args, require_policy=True)
    try:
        outcome = runtime.check_canary(_target(args, tokens))
        print(json.dumps(_outcome_json(outcome), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_audit_attestation(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(args, require_policy=True)
    try:
        outcome = runtime.audit_attestation(_target(args, tokens))
        print(json.dumps(_outcome_json(outcome), sort_keys=True))
        return 0 if outcome.status == "attestation_verified" else 1
    finally:
        runtime.close()
        ledger.close()


def cmd_runtime_run_epoch(args: argparse.Namespace) -> int:
    runtime, ledger, tokens = _build_runtime(
        args,
        require_policy=True,
        require_report_audience=True,
    )
    try:
        run = runtime.run_epoch(
            args.source_epoch,
            _target(args, tokens),
            publish=args.publish,
        )
        if getattr(args, "pretty", False):
            _format_run_pretty(run)
        else:
            print(json.dumps(_run_json(run), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_status(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        print(json.dumps(dict(runtime.status()), sort_keys=True))
        return 0
    finally:
        ledger.close()


def _score_class_time(value: str, label: str) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label} must be a timezone-aware ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _write_score_class_report(path: str, body: bytes) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(temporary, flags, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def cmd_runtime_export_score_class(args: argparse.Namespace) -> int:
    ledger = Ledger(args.ledger_db)
    try:
        existing = ledger.get_score_class_export(
            args.epoch_id,
            network=args.score_network,
            netuid=args.score_netuid,
            class_id=args.class_id,
            source_id=args.source_id,
        )
        replayed = existing is not None
        if existing is not None:
            report = bytes(existing["report_body"])
        else:
            if not args.development and not args.evidence_base_uri:
                raise ValueError(
                    "production score-class export requires --evidence-base-uri "
                    "for validator provenance"
                )
            generated_at = (
                datetime.datetime.now(datetime.timezone.utc)
                if args.generated_at is None
                else _score_class_time(args.generated_at, "generated_at")
            )
            report = export_score_class_report(
                ledger,
                args.epoch_id,
                network=args.score_network,
                netuid=args.score_netuid,
                class_id=args.class_id,
                source_id=args.source_id,
                signing_key_id=args.signing_key_id,
                private_key_seed=_load_private_seed(
                    args.signing_key_file,
                    production_mode=not args.development,
                    label="score-class signing key",
                ),
                generated_at=generated_at,
                valid_until=_score_class_time(args.valid_until, "valid_until"),
                valid_from_block=args.valid_from_block,
                valid_until_block=args.valid_until_block,
                verifier_digest=args.verifier_digest,
                policy_digest=args.policy_digest,
                previous_report_id=args.previous_report_id,
                evidence_base_uri=args.evidence_base_uri,
            )
        _write_score_class_report(args.output, report)
        document = json.loads(report)
        print(
            json.dumps(
                {
                    "class_id": document["class_id"],
                    "entries": len(document["entries"]),
                    "output": str(Path(args.output).expanduser()),
                    "replayed": replayed,
                    "report_id": document["report_id"],
                    "source_epoch": document["source_epoch"],
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        ledger.close()


def cmd_runtime_retry_publish(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        acknowledgement = runtime.publish_completed(args.epoch_id)
        if getattr(args, "pretty", False):
            _format_publish_pretty(args.epoch_id, dict(acknowledgement))
        else:
            print(json.dumps(dict(acknowledgement), sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_abort_running(args: argparse.Namespace) -> int:
    runtime, ledger, _ = _build_runtime(args)
    try:
        epoch_id = runtime.abort_running()
        print(json.dumps({"aborted_epoch_id": epoch_id}, sort_keys=True))
        return 0
    finally:
        ledger.close()


def cmd_runtime_abandon_complete(args: argparse.Namespace) -> int:
    """Recovery command: abandon a 'complete' epoch that can never publish.

    See ``ConfidentialRuntime.abandon_completed`` / ``Ledger.abandon_completed_epoch``
    for the invariants (audited, one-way, never payable, never mutates report bytes).
    """
    runtime, ledger, _ = _build_runtime(args)
    try:
        epoch_id = runtime.abandon_completed(args.epoch_id, args.reason)
        row = ledger.get_epoch(epoch_id)
        assert row is not None
        print(
            json.dumps(
                {
                    "abandoned_epoch_id": epoch_id,
                    "reason": row["abandon_reason"],
                    "abandoned_at": row["abandoned_at"],
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        ledger.close()


def cmd_runtime_recover_gpu_identities(args: argparse.Namespace) -> int:
    """Authenticate and audit deterministic recovery of crash-left GPU claims."""

    outcome = GpuIdentityRegistry.recover_interrupted(
        args.gpu_identity_db,
        identity_digest_key=_load_gpu_identity_key(
            args.gpu_identity_key_file,
            production_mode=not args.development,
        ),
        reason=args.reason,
        production_mode=not args.development,
        generation_anchor_path=args.gpu_identity_anchor_file,
    )
    print(json.dumps(dict(outcome), sort_keys=True))
    return 0


def cmd_runtime_initialize_gpu_identities(args: argparse.Namespace) -> int:
    """Perform the explicit one-time creation of production GPU identity state."""

    registry = GpuIdentityRegistry(
        args.gpu_identity_db,
        identity_digest_key=_load_gpu_identity_key(
            args.gpu_identity_key_file,
            production_mode=not args.development,
        ),
        production_mode=not args.development,
        generation_anchor_path=args.gpu_identity_anchor_file,
        initialize=True,
    )
    print(
        json.dumps(
            {
                "generation_anchor": str(args.gpu_identity_anchor_file),
                "identity_database": str(args.gpu_identity_db),
                "initialized": True,
                "production_ready": registry.production_ready,
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_lifecycle_status(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    store = RegistryStore(args.registry_db)
    snapshot = store.lifecycle_snapshot(args.hotkey)
    payload = snapshot.operator_dict() if args.operator else snapshot.public_dict()
    print(json.dumps({"hotkey": args.hotkey, **payload}, sort_keys=True))
    return 0


def cmd_lifecycle_history(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    store = RegistryStore(args.registry_db)
    history = store.lifecycle_history(args.hotkey, operator=args.operator)
    print(
        json.dumps(
            {"hotkey": args.hotkey, "events": list(history)},
            sort_keys=True,
        )
    )
    return 0


def cmd_lifecycle_reenroll(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    snapshot = RegistryStore(args.registry_db).reenroll_lifecycle(args.hotkey)
    print(json.dumps({"hotkey": args.hotkey, **snapshot.public_dict()}, sort_keys=True))
    return 0


def cmd_lifecycle_retire(args: argparse.Namespace) -> int:
    if not Path(args.registry_db).is_file():
        raise ValueError("registry database does not exist")
    snapshot = RegistryStore(args.registry_db).retire_lifecycle(
        args.hotkey,
        removed=args.removed,
    )
    print(json.dumps({"hotkey": args.hotkey, **snapshot.public_dict()}, sort_keys=True))
    return 0


# --------------------------------------------------------------------------
# argparse wiring
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral", description="Cathedral operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_census = sub.add_parser("census", help="run the local CC capability probe")
    p_census.add_argument(
        "--json",
        action="store_true",
        help="machine-readable output (passed through to cathedral.census)",
    )
    p_census.set_defaults(func=cmd_census)

    p_verify = sub.add_parser("verify-quote", help="check a mock attested quote against a policy")
    p_verify.add_argument("--measurement", required=True, help="the (mock) attested measurement")
    p_verify.add_argument("--tcb", type=int, required=True, help="the (mock) attested tcb version")
    p_verify.add_argument(
        "--allowed-measurement",
        action="append",
        required=True,
        dest="allowed_measurement",
        help="repeatable; one or more measurements the policy allows",
    )
    p_verify.add_argument("--min-tcb", type=int, default=0)
    p_verify.set_defaults(func=cmd_verify_quote)

    p_work = sub.add_parser("work", help="drive the SAT-lane work queue")
    work_sub = p_work.add_subparsers(dest="work_command", required=True)

    p_submit = work_sub.add_parser("submit", help="enqueue a customer job")
    p_submit.add_argument(
        "--n-vars", type=int, default=0, help="variable count (paired with --clauses)"
    )
    p_submit.add_argument(
        "--clauses",
        default=None,
        help="JSON list of clauses (DIMACS ints); omit to submit canonical backfill work",
    )
    p_submit.add_argument("--seed", type=int, default=None)
    p_submit.add_argument("--ledger-db", required=True)
    p_submit.add_argument("--customer-id", required=True)
    p_submit.add_argument("--idempotency-key")
    p_submit.set_defaults(func=cmd_work_submit)

    p_status = work_sub.add_parser("status", help="report queue/backfill state")
    p_status.add_argument("--ledger-db", required=True)
    p_status.add_argument("--job-id")
    p_status.set_defaults(func=cmd_work_status)

    p_prune = work_sub.add_parser("prune", help="delete bounded terminal customer-job history")
    p_prune.add_argument("--ledger-db", required=True)
    p_prune.add_argument("--resolved-before", required=True)
    p_prune.add_argument("--customer-id")
    p_prune.add_argument("--limit", type=int, default=1000)
    p_prune.add_argument("--confirm", action="store_true")
    p_prune.set_defaults(func=cmd_work_prune)

    p_worker = sub.add_parser("worker", help="run a miner worker")
    worker_sub = p_worker.add_subparsers(dest="worker_command", required=True)
    p_serve = worker_sub.add_parser("serve", help="serve one configured miner hotkey")
    p_serve.add_argument("--hotkey", required=True)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8081)
    p_serve.add_argument("--bearer-token-env", default=DEFAULT_WORKER_BEARER_ENV)
    p_serve.add_argument(
        "--tls-certificate",
        help="PEM certificate served directly by the worker",
    )
    p_serve.add_argument(
        "--tls-private-key",
        help="owner-only PEM private key kept inside the worker guest",
    )
    p_serve.add_argument("--development-no-auth", action="store_true")
    p_serve.add_argument("--development-allow-non-loopback", action="store_true")
    p_serve.add_argument(
        "--allow-customer-sat",
        action="store_true",
        help="accept bounded customer SAT jobs; requires bearer auth and channel binding",
    )
    p_serve.add_argument(
        "--gpu-composite",
        action="store_true",
        help=(
            "collect bound TDX plus confidential-GPU evidence; requires CATHEDRAL_GPU_COLLECT_CMD"
        ),
    )
    p_serve.add_argument(
        "--channel-binding-type",
        choices=[binding.value for binding in ChannelBindingType],
    )
    p_serve.add_argument(
        "--channel-binding-digest",
        help="32-byte channel public-key digest as 64 lowercase hex characters",
    )
    p_serve.set_defaults(func=cmd_worker_serve)

    p_policy = sub.add_parser("policy-registry", help="verify signed public measurement policy")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_policy_verify = policy_sub.add_parser("verify", help="verify and inspect a registry")
    p_policy_verify.add_argument("--registry", required=True)
    p_policy_verify.add_argument("--trusted-keys", required=True)
    p_policy_verify.add_argument("--max-age-seconds", type=int, default=86400)
    p_policy_verify.add_argument(
        "--historical-at",
        help="verify at canonical UTC receipt time instead of current admission time",
    )
    p_policy_verify.set_defaults(func=cmd_policy_registry_verify)

    p_receipt = sub.add_parser("receipt", help="verify assurance receipts")
    receipt_sub = p_receipt.add_subparsers(dest="receipt_command", required=True)
    p_receipt_verify = receipt_sub.add_parser(
        "verify", help="offline verification of exact signed receipt bytes"
    )
    p_receipt_verify.add_argument("--receipt", required=True)
    p_receipt_verify.add_argument("--policy-registry", required=True)
    p_receipt_verify.add_argument("--trusted-keys", required=True)
    p_receipt_verify.add_argument(
        "--key-registry",
        help="newer registry used to enforce receipt-key retirement or revocation",
    )
    p_receipt_verify.add_argument("--key-registry-trusted-keys")
    p_receipt_verify.add_argument("--key-registry-max-age-seconds", type=int, default=86400)
    p_receipt_verify.set_defaults(func=cmd_receipt_verify)

    p_lifecycle = sub.add_parser("lifecycle", help="inspect worker attestation lifecycle state")
    lifecycle_sub = p_lifecycle.add_subparsers(dest="lifecycle_command", required=True)
    p_lifecycle_status = lifecycle_sub.add_parser(
        "status", help="show the current customer-safe worker state"
    )
    p_lifecycle_status.add_argument("--registry-db", required=True)
    p_lifecycle_status.add_argument("--hotkey", required=True)
    p_lifecycle_status.add_argument(
        "--operator",
        action="store_true",
        help="include internal evidence, policy, retry, and event identifiers",
    )
    p_lifecycle_status.set_defaults(func=cmd_lifecycle_status)

    p_lifecycle_history = lifecycle_sub.add_parser(
        "history", help="show append-only worker transition history"
    )
    p_lifecycle_history.add_argument("--registry-db", required=True)
    p_lifecycle_history.add_argument("--hotkey", required=True)
    p_lifecycle_history.add_argument(
        "--operator",
        action="store_true",
        help="include internal evidence, policy, retry, and error details",
    )
    p_lifecycle_history.set_defaults(func=cmd_lifecycle_history)

    p_lifecycle_reenroll = lifecycle_sub.add_parser(
        "reenroll",
        help="start a new pending generation after failed, retired, or revoked state",
    )
    p_lifecycle_reenroll.add_argument("--registry-db", required=True)
    p_lifecycle_reenroll.add_argument("--hotkey", required=True)
    p_lifecycle_reenroll.set_defaults(func=cmd_lifecycle_reenroll)

    p_lifecycle_retire = lifecycle_sub.add_parser(
        "retire", help="stop refresh and score eligibility for a worker"
    )
    p_lifecycle_retire.add_argument("--registry-db", required=True)
    p_lifecycle_retire.add_argument("--hotkey", required=True)
    p_lifecycle_retire.add_argument(
        "--removed",
        action="store_true",
        help="finish directly in retired instead of leaving the worker retiring",
    )
    p_lifecycle_retire.set_defaults(func=cmd_lifecycle_retire)

    p_runtime = sub.add_parser("runtime", help="operate confidential-compute report epochs")
    runtime_sub = p_runtime.add_subparsers(dest="runtime_command", required=True)

    def add_runtime_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--registry-db", required=True)
        command.add_argument("--ledger-db", required=True)
        command.add_argument("--measurements-file")
        command.add_argument("--policy-registry")
        command.add_argument("--policy-registry-keys")
        command.add_argument(
            "--policy-registry-keys-digest",
            help="independently configured sha256 digest of the trusted-key file",
        )
        command.add_argument("--policy-registry-state")
        command.add_argument("--policy-registry-min-release", type=int)
        command.add_argument("--policy-registry-pinned-release", type=int)
        command.add_argument("--policy-registry-pinned-digest")
        command.add_argument("--policy-registry-max-age-seconds", type=int, default=86400)
        command.add_argument("--receipt-signing-key-id")
        command.add_argument("--receipt-signing-key-file")
        command.add_argument(
            "--gpu-profile-id",
            help="active gpu_cc profile id from the verified policy registry",
        )
        command.add_argument(
            "--gpu-identity-db",
            help="durable pseudonymous GPU identity-claim database",
        )
        command.add_argument(
            "--gpu-identity-key-file",
            help="owner-only file containing a 32-byte base64 identity key",
        )
        command.add_argument(
            "--gpu-identity-anchor-file",
            help="external protected monotonic generation anchor",
        )
        command.add_argument("--tokens-file", default=None)
        command.add_argument("--miner-timeout-seconds", type=float, default=10.0)
        command.add_argument("--miner-attempts", type=int, default=2)
        command.add_argument("--max-workers", type=int, default=8)
        command.add_argument("--reattestation-failures-before-failed", type=int, default=3)
        command.add_argument("--reattestation-retry-base-seconds", type=int, default=5)
        command.add_argument("--reattestation-retry-maximum-seconds", type=int, default=300)
        command.add_argument("--reattestation-retry-jitter-seconds", type=int, default=5)
        command.add_argument("--customer-job-lease-seconds", type=int, default=120)
        command.add_argument("--customer-job-max-attempts", type=int, default=3)
        command.add_argument("--development", action="store_true")
        command.add_argument("--publisher-endpoint", default=None)
        command.add_argument("--publisher-bearer-env", default=DEFAULT_PUBLISHER_BEARER_ENV)
        command.add_argument("--publisher-hmac-env", default=DEFAULT_PUBLISHER_HMAC_ENV)
        command.add_argument(
            "--score-network",
            help="exact network audience embedded in each frozen score report",
        )
        command.add_argument(
            "--score-netuid",
            type=int,
            help="subnet UID audience embedded in each frozen score report",
        )

    def add_canary(command: argparse.ArgumentParser) -> None:
        command.add_argument("--canary-hotkey", required=True)
        command.add_argument("--canary-endpoint", required=True)

    p_canary = runtime_sub.add_parser(
        "canary", help="run fresh requested-tier attestation and SAT canary"
    )
    add_runtime_common(p_canary)
    add_canary(p_canary)
    p_canary.set_defaults(func=cmd_runtime_canary)

    p_audit = runtime_sub.add_parser(
        "audit-attestation",
        help="verify fresh evidence and channel binding without work or scoring",
    )
    add_runtime_common(p_audit)
    add_canary(p_audit)
    p_audit.set_defaults(func=cmd_runtime_audit_attestation)

    p_run = runtime_sub.add_parser("run-epoch", help="freeze one complete report")
    add_runtime_common(p_run)
    add_canary(p_run)
    p_run.add_argument("--source-epoch", type=int, required=True)
    p_run.add_argument("--publish", action="store_true")
    p_run.add_argument(
        "--pretty",
        action="store_true",
        help="human-readable epoch summary (default: JSON)",
    )
    p_run.set_defaults(func=cmd_runtime_run_epoch)

    p_runtime_status = runtime_sub.add_parser("status", help="show restart-blocking state")
    p_runtime_status.add_argument("--ledger-db", required=True)
    p_runtime_status.set_defaults(func=cmd_runtime_status)

    p_export_class = runtime_sub.add_parser(
        "export-score-class",
        help="export a frozen receipt-backed report for an independent validator",
    )
    p_export_class.add_argument("--ledger-db", required=True)
    p_export_class.add_argument("--epoch-id", type=int, required=True)
    p_export_class.add_argument("--score-network", required=True)
    p_export_class.add_argument("--score-netuid", type=int, required=True)
    p_export_class.add_argument("--class-id", default="confidential_compute")
    p_export_class.add_argument("--source-id", default="cathedralconfidential")
    p_export_class.add_argument("--signing-key-id", required=True)
    p_export_class.add_argument("--signing-key-file", required=True)
    p_export_class.add_argument("--generated-at")
    p_export_class.add_argument("--valid-until", required=True)
    p_export_class.add_argument("--valid-from-block", type=int, required=True)
    p_export_class.add_argument("--valid-until-block", type=int, required=True)
    p_export_class.add_argument("--verifier-digest", required=True)
    p_export_class.add_argument("--policy-digest")
    p_export_class.add_argument("--previous-report-id")
    p_export_class.add_argument("--evidence-base-uri")
    p_export_class.add_argument("--output", required=True)
    p_export_class.add_argument(
        "--development",
        action="store_true",
        help="relax production signing-key ownership and mode checks",
    )
    p_export_class.set_defaults(func=cmd_runtime_export_score_class)

    p_retry = runtime_sub.add_parser("retry-publish", help="publish frozen report bytes")
    p_retry.add_argument("--ledger-db", required=True)
    p_retry.add_argument("--publisher-endpoint", required=True)
    p_retry.add_argument("--publisher-bearer-env", default=DEFAULT_PUBLISHER_BEARER_ENV)
    p_retry.add_argument("--publisher-hmac-env", default=DEFAULT_PUBLISHER_HMAC_ENV)
    p_retry.add_argument("--score-network", required=True)
    p_retry.add_argument("--score-netuid", type=int, required=True)
    p_retry.add_argument("--epoch-id", type=int, required=True)
    p_retry.add_argument(
        "--pretty",
        action="store_true",
        help="human-readable publish summary (default: JSON)",
    )
    p_retry.set_defaults(func=cmd_runtime_retry_publish)

    p_abort = runtime_sub.add_parser("abort-running", help="abort the running epoch")
    p_abort.add_argument("--ledger-db", required=True)
    p_abort.set_defaults(func=cmd_runtime_abort_running)

    p_abandon = runtime_sub.add_parser(
        "abandon-complete",
        help=(
            "abandon a completed-but-unpublished epoch that can never publish "
            "(e.g. its report is too old for the ingest service's first-publish window)"
        ),
    )
    p_abandon.add_argument("--ledger-db", required=True)
    p_abandon.add_argument("--epoch-id", type=int, required=True)
    p_abandon.add_argument(
        "--reason",
        required=True,
        help="nonempty operator justification; recorded in the ledger audit trail",
    )
    p_abandon.set_defaults(func=cmd_runtime_abandon_complete)

    p_gpu_recovery = runtime_sub.add_parser(
        "recover-gpu-identities",
        help="reconcile interrupted GPU claims and record an authenticated audit event",
    )
    p_gpu_recovery.add_argument("--gpu-identity-db", required=True)
    p_gpu_recovery.add_argument("--gpu-identity-key-file", required=True)
    p_gpu_recovery.add_argument("--gpu-identity-anchor-file", required=True)
    p_gpu_recovery.add_argument(
        "--reason",
        required=True,
        help="operator justification recorded in the GPU identity audit trail",
    )
    p_gpu_recovery.add_argument(
        "--development",
        action="store_true",
        help="relax production ownership checks for a local recovery exercise",
    )
    p_gpu_recovery.set_defaults(func=cmd_runtime_recover_gpu_identities)

    p_gpu_initialize = runtime_sub.add_parser(
        "initialize-gpu-identities",
        help="perform one-time creation of the GPU identity database and external anchor",
    )
    p_gpu_initialize.add_argument("--gpu-identity-db", required=True)
    p_gpu_initialize.add_argument("--gpu-identity-key-file", required=True)
    p_gpu_initialize.add_argument("--gpu-identity-anchor-file", required=True)
    p_gpu_initialize.add_argument(
        "--development",
        action="store_true",
        help="relax production path separation and ownership checks for a local exercise",
    )
    p_gpu_initialize.set_defaults(func=cmd_runtime_initialize_gpu_identities)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        # Any exception text may echo request/response context that embeds a
        # credential (e.g. a token-mapping load error); sanitize before it
        # reaches logs, same as the outcome/run JSON and --pretty paths.
        print(json.dumps({"error": _sanitize_error(str(exc), maxlen=300)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
