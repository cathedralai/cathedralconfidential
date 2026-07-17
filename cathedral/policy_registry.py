"""Signed, immutable, rollback-resistant public policy registries."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.common import Policy


REGISTRY_SCHEMA = "cathedral_policy_registry_v1"
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_REGISTRY_PROFILES = 1024
MAX_POLICY_LIST_ITEMS = 4096
MAX_METADATA_DEPTH = 32
MAX_METADATA_NODES = 10_000
MAX_METADATA_STRING_BYTES = 16_384
MAX_METADATA_KEY_BYTES = 256
MAX_SQLITE_INTEGER = 2**63 - 1
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "release",
        "generated_at",
        "valid_from",
        "valid_until",
        "signing_key_id",
        "profiles",
        "metadata",
        "signature",
    }
)
_PROFILE_KEYS = frozenset(
    {
        "id",
        "kind",
        "status",
        "status_changed_at",
        "valid_from",
        "valid_until",
        "retire_at",
        "measurements",
        "runtime_measurements",
        "allowed_firmware",
        "min_tcb",
        "tdx_allowed_tcb_statuses",
        "tdx_allowed_advisories",
        "metadata",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_PROFILE_KINDS = frozenset({"cpu_tdx", "cpu_snp", "gpu_cc"})
_PROFILE_STATUSES = frozenset({"active", "retiring", "retired", "revoked"})
_TRANSITIONS = {
    "active": frozenset({"active", "retiring", "revoked"}),
    "retiring": frozenset({"retiring", "retired", "revoked"}),
    "retired": frozenset({"retired"}),
    "revoked": frozenset({"revoked"}),
}


class PolicyRegistryError(ValueError):
    """A public registry failed schema, signature, freshness, or state checks."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyRegistryError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_registry_json(data: bytes | str) -> dict[str, object]:
    try:
        encoded_length = len(data) if isinstance(data, bytes) else len(data.encode("utf-8"))
        if encoded_length > MAX_REGISTRY_BYTES:
            raise PolicyRegistryError("registry exceeds the maximum encoded size")
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        if not isinstance(text, str):
            raise TypeError
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=lambda _value: (_ for _ in ()).throw(
                PolicyRegistryError("floating-point JSON is not canonical")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                PolicyRegistryError("non-finite JSON is not canonical")
            ),
        )
    except PolicyRegistryError:
        raise
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise PolicyRegistryError("registry is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise PolicyRegistryError("registry must be a JSON object")
    return parsed


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PolicyRegistryError("registry contains a non-canonical value") from exc


def canonical_signed_bytes(document: Mapping[str, object]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical_json(unsigned)


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise PolicyRegistryError(f"{name} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise PolicyRegistryError(f"{name} must be canonical UTC time") from exc


def _string_list(value: object, name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or len(item) > 512 for item in value
    ):
        raise PolicyRegistryError(f"{name} must be a list of bounded strings")
    if len(value) > MAX_POLICY_LIST_ITEMS:
        raise PolicyRegistryError(f"{name} contains too many entries")
    if not allow_empty and not value:
        raise PolicyRegistryError(f"{name} cannot be empty")
    if len(set(value)) != len(value):
        raise PolicyRegistryError(f"{name} cannot contain duplicates")
    return tuple(value)


def _validate_metadata(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise PolicyRegistryError(f"{name} must be an object")
    nodes = 0

    def freeze(item: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_METADATA_NODES or depth > MAX_METADATA_DEPTH:
            raise PolicyRegistryError(f"{name} is too deeply nested or complex")
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_METADATA_STRING_BYTES:
                raise PolicyRegistryError(f"{name} contains an oversized string")
            return item
        if isinstance(item, int) and not isinstance(item, bool):
            return item
        if isinstance(item, list):
            return tuple(freeze(child, depth + 1) for child in item)
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            if any(len(key.encode("utf-8")) > MAX_METADATA_KEY_BYTES for key in item):
                raise PolicyRegistryError(f"{name} contains an oversized key")
            return MappingProxyType(
                {key: freeze(child, depth + 1) for key, child in item.items()}
            )
        raise PolicyRegistryError(f"{name} contains a non-canonical value")

    return freeze(value, 0)  # type: ignore[return-value]


@dataclass(frozen=True)
class PolicyProfile:
    profile_id: str
    kind: str
    status: str
    status_changed_at: datetime
    valid_from: datetime
    valid_until: datetime
    retire_at: datetime | None
    measurements: tuple[str, ...]
    runtime_measurements: tuple[str, ...]
    allowed_firmware: tuple[str, ...]
    min_tcb: int
    tdx_allowed_tcb_statuses: tuple[str, ...]
    tdx_allowed_advisories: tuple[str, ...]
    metadata: Mapping[str, object]

    def eligible_at(self, when: datetime) -> bool:
        if self.status not in {"active", "retiring"}:
            return False
        if not self.valid_from <= self.status_changed_at <= when < self.valid_until:
            return False
        return not (
            self.status == "retiring"
            and self.retire_at is not None
            and when >= self.retire_at
        )


@dataclass(frozen=True)
class PolicyRegistrySnapshot:
    release: int
    generated_at: datetime
    valid_from: datetime
    valid_until: datetime
    signing_key_id: str
    digest: str
    profiles: tuple[PolicyProfile, ...]
    metadata: Mapping[str, object]
    canonical_document: bytes

    def profile_states(self) -> Mapping[str, str]:
        return MappingProxyType(
            {profile.profile_id: profile.status for profile in self.profiles}
        )

    def to_policy(self, *, at: datetime | None = None) -> Policy:
        when = at or datetime.now(UTC)
        if when.tzinfo is None or when.utcoffset() != timedelta(0):
            raise PolicyRegistryError("policy evaluation time must be UTC")
        eligible = [
            profile
            for profile in self.profiles
            if profile.kind == "cpu_tdx" and profile.eligible_at(when)
        ]
        if not eligible:
            raise PolicyRegistryError("registry has no eligible CPU TDX profile")
        controls = {
            (
                profile.min_tcb,
                frozenset(profile.tdx_allowed_tcb_statuses),
                frozenset(profile.tdx_allowed_advisories),
                frozenset(profile.allowed_firmware),
            )
            for profile in eligible
        }
        if len(controls) != 1:
            raise PolicyRegistryError(
                "overlapping CPU TDX profiles must share security controls"
            )
        min_tcb, statuses, advisories, firmware = controls.pop()
        measurements = {
            measurement for profile in eligible for measurement in profile.measurements
        }
        return Policy(
            allowed_measurements=measurements,
            min_tcb=min_tcb,
            allowed_firmware=set(firmware),
            tdx_strict=True,
            tdx_allowed_tcb_statuses=set(statuses),
            tdx_allowed_advisories=set(advisories),
            registry_release=self.release,
            registry_digest=self.digest,
            registry_profile_ids=tuple(sorted(profile.profile_id for profile in eligible)),
        )


def _profile(raw: object, registry_from: datetime, registry_until: datetime) -> PolicyProfile:
    if not isinstance(raw, dict) or frozenset(raw) != _PROFILE_KEYS:
        raise PolicyRegistryError("profile contains missing or unknown critical fields")
    profile_id = raw["id"]
    kind = raw["kind"]
    status = raw["status"]
    if not isinstance(profile_id, str) or _ID_RE.fullmatch(profile_id) is None:
        raise PolicyRegistryError("profile id is invalid")
    if kind not in _PROFILE_KINDS:
        raise PolicyRegistryError("profile kind is unsupported")
    if status not in _PROFILE_STATUSES:
        raise PolicyRegistryError("profile status is unsupported")
    changed = _timestamp(raw["status_changed_at"], "profile status_changed_at")
    valid_from = _timestamp(raw["valid_from"], "profile valid_from")
    valid_until = _timestamp(raw["valid_until"], "profile valid_until")
    if not registry_from <= valid_from < valid_until <= registry_until:
        raise PolicyRegistryError("profile validity must fit inside registry validity")
    if not valid_from <= changed < valid_until:
        raise PolicyRegistryError("profile status change must fall inside its validity")
    retire_raw = raw["retire_at"]
    retire_at = None if retire_raw is None else _timestamp(retire_raw, "profile retire_at")
    if status == "retiring":
        if retire_at is None or not changed <= retire_at <= valid_until:
            raise PolicyRegistryError("retiring profile requires a bounded retire_at")
    elif status == "active" and retire_at is not None:
        raise PolicyRegistryError("active profile cannot set retire_at")
    elif status in {"retired", "revoked"} and retire_at != changed:
        raise PolicyRegistryError(
            "terminal profile retire_at must equal its status transition time"
        )
    min_tcb = raw["min_tcb"]
    if (
        isinstance(min_tcb, bool)
        or not isinstance(min_tcb, int)
        or not 0 <= min_tcb <= MAX_SQLITE_INTEGER
    ):
        raise PolicyRegistryError("profile min_tcb must be a bounded nonnegative integer")
    measurements = _string_list(
        raw["measurements"], "profile measurements", allow_empty=kind == "gpu_cc"
    )
    runtime_measurements = _string_list(
        raw["runtime_measurements"], "profile runtime_measurements"
    )
    firmware = _string_list(raw["allowed_firmware"], "profile allowed_firmware")
    statuses = _string_list(
        raw["tdx_allowed_tcb_statuses"],
        "profile tdx_allowed_tcb_statuses",
        allow_empty=kind != "cpu_tdx",
    )
    advisories = _string_list(
        raw["tdx_allowed_advisories"], "profile tdx_allowed_advisories"
    )
    if kind != "cpu_tdx" and (statuses or advisories):
        raise PolicyRegistryError("non-TDX profile cannot set TDX controls")
    return PolicyProfile(
        profile_id,
        kind,
        status,
        changed,
        valid_from,
        valid_until,
        retire_at,
        measurements,
        runtime_measurements,
        firmware,
        min_tcb,
        statuses,
        advisories,
        _validate_metadata(raw["metadata"], "profile metadata"),
    )


def verify_registry(
    data: bytes | str,
    trusted_keys: Mapping[str, bytes],
    *,
    now: datetime | None = None,
    max_age_seconds: int = 86400,
    historical_at: datetime | None = None,
) -> PolicyRegistrySnapshot:
    document = parse_registry_json(data)
    if frozenset(document) != _TOP_LEVEL_KEYS:
        raise PolicyRegistryError("registry contains missing or unknown critical fields")
    if document["schema"] != REGISTRY_SCHEMA:
        raise PolicyRegistryError("registry schema is unsupported")
    release = document["release"]
    if (
        isinstance(release, bool)
        or not isinstance(release, int)
        or not 0 < release <= MAX_SQLITE_INTEGER
    ):
        raise PolicyRegistryError("registry release must be a bounded positive integer")
    key_id = document["signing_key_id"]
    if not isinstance(key_id, str) or _ID_RE.fullmatch(key_id) is None:
        raise PolicyRegistryError("registry signing key id is invalid")
    key = trusted_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise PolicyRegistryError("registry signing key is not trusted")
    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise PolicyRegistryError("registry signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise PolicyRegistryError("registry signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise PolicyRegistryError("registry signature is not canonical base64") from exc
    if len(signature_bytes) != 64:
        raise PolicyRegistryError("registry signature must be 64 bytes")
    signed = canonical_signed_bytes(document)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, signed)
    except (InvalidSignature, ValueError) as exc:
        raise PolicyRegistryError("registry signature verification failed") from exc

    generated = _timestamp(document["generated_at"], "registry generated_at")
    valid_from = _timestamp(document["valid_from"], "registry valid_from")
    valid_until = _timestamp(document["valid_until"], "registry valid_until")
    if not generated <= valid_from < valid_until:
        raise PolicyRegistryError("registry validity window is invalid")
    check_time = historical_at or now or datetime.now(UTC)
    if check_time.tzinfo is None or check_time.utcoffset() != timedelta(0):
        raise PolicyRegistryError("registry verification time must be UTC")
    if not valid_from <= check_time < valid_until:
        raise PolicyRegistryError("registry is outside its validity window")
    if historical_at is None:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds <= 0
        ):
            raise PolicyRegistryError("registry maximum age must be positive")
        if generated > check_time + timedelta(minutes=5):
            raise PolicyRegistryError("registry generation time is in the future")
        if check_time - generated > timedelta(seconds=max_age_seconds):
            raise PolicyRegistryError("registry is too stale for admission")

    profiles_raw = document["profiles"]
    if (
        not isinstance(profiles_raw, list)
        or not profiles_raw
        or len(profiles_raw) > MAX_REGISTRY_PROFILES
    ):
        raise PolicyRegistryError("registry profiles must be a nonempty list")
    profiles = tuple(_profile(raw, valid_from, valid_until) for raw in profiles_raw)
    if any(
        profile.status_changed_at > check_time
        and not (
            profile.status == "active"
            and profile.status_changed_at == profile.valid_from
        )
        for profile in profiles
    ):
        raise PolicyRegistryError("profile status transition is not yet effective")
    ids = [profile.profile_id for profile in profiles]
    if len(set(ids)) != len(ids):
        raise PolicyRegistryError("registry profile ids must be unique")
    canonical_document = canonical_json(document)
    return PolicyRegistrySnapshot(
        release=release,
        generated_at=generated,
        valid_from=valid_from,
        valid_until=valid_until,
        signing_key_id=key_id,
        digest="sha256:" + hashlib.sha256(canonical_document).hexdigest(),
        profiles=profiles,
        metadata=_validate_metadata(document["metadata"], "registry metadata"),
        canonical_document=canonical_document,
    )


def sign_registry(
    unsigned_document: Mapping[str, object], private_key: bytes
) -> dict[str, object]:
    if "signature" in unsigned_document:
        raise PolicyRegistryError("unsigned registry must not contain signature")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise PolicyRegistryError("Ed25519 private key seed must be 32 bytes")
    document = dict(unsigned_document)
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        canonical_json(document)
    )
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return document


class PolicyRegistryState:
    """Durable release high-water mark and profile-transition guard."""

    def __init__(
        self,
        path: str | Path,
        *,
        production_mode: bool = True,
        minimum_release: int | None = None,
        pinned_release: int | None = None,
        pinned_digest: str | None = None,
    ) -> None:
        if production_mode and minimum_release is None and pinned_release is None:
            raise PolicyRegistryError(
                "production registry bootstrap requires a minimum or pinned release"
            )
        if minimum_release is not None and (
            isinstance(minimum_release, bool)
            or not isinstance(minimum_release, int)
            or not 0 < minimum_release <= MAX_SQLITE_INTEGER
        ):
            raise PolicyRegistryError("minimum release must be positive")
        if (pinned_release is None) != (pinned_digest is None):
            raise PolicyRegistryError("pinned release and digest must be supplied together")
        if pinned_release is not None and (
            isinstance(pinned_release, bool)
            or not isinstance(pinned_release, int)
            or not 0 < pinned_release <= MAX_SQLITE_INTEGER
            or not isinstance(pinned_digest, str)
            or _DIGEST_RE.fullmatch(pinned_digest) is None
        ):
            raise PolicyRegistryError("pinned checkpoint is invalid")
        self.path = str(path)
        self.minimum_release = minimum_release
        self.pinned_release = pinned_release
        self.pinned_digest = pinned_digest
        self._lock = threading.RLock()
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policy_registry_state (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        release INTEGER NOT NULL,
                        digest TEXT NOT NULL,
                        profile_states_json TEXT NOT NULL,
                        accepted_at TEXT NOT NULL
                    )
                    """
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def current(self) -> Mapping[str, object] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT release, digest, profile_states_json, accepted_at "
                "FROM policy_registry_state WHERE singleton = 1"
            ).fetchone()
        return MappingProxyType(dict(row)) if row is not None else None

    @staticmethod
    def _decode_profile_states(encoded: object) -> dict[str, dict[str, str]]:
        if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > MAX_REGISTRY_BYTES:
            raise PolicyRegistryError("persisted registry profile state is invalid")
        try:
            states = json.loads(encoded, object_pairs_hook=_reject_duplicate_keys)
        except (PolicyRegistryError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicyRegistryError("persisted registry profile state is invalid") from exc
        if not isinstance(states, dict):
            raise PolicyRegistryError("persisted registry profile state is invalid")
        for profile_id, state in states.items():
            if (
                not isinstance(profile_id, str)
                or _ID_RE.fullmatch(profile_id) is None
                or not isinstance(state, dict)
                or frozenset(state) != {"status", "status_changed_at"}
                or not isinstance(state["status"], str)
                or state["status"] not in _PROFILE_STATUSES
            ):
                raise PolicyRegistryError("persisted registry profile state is invalid")
            _timestamp(
                state["status_changed_at"],
                "persisted profile status_changed_at",
            )
        return states

    def accept(self, snapshot: PolicyRegistrySnapshot) -> None:
        if self.minimum_release is not None and snapshot.release < self.minimum_release:
            raise PolicyRegistryError("registry release is below the configured minimum")
        states = {
            profile.profile_id: {
                "status": profile.status,
                "status_changed_at": profile.status_changed_at.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
            for profile in snapshot.profiles
        }
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT release, digest, profile_states_json "
                    "FROM policy_registry_state WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    if self.pinned_release is not None:
                        if (
                            snapshot.release != self.pinned_release
                            or snapshot.digest != self.pinned_digest
                        ):
                            raise PolicyRegistryError(
                                "fresh state must bootstrap from the pinned checkpoint"
                            )
                else:
                    prior_release = int(row["release"])
                    if snapshot.release == prior_release:
                        if snapshot.digest == row["digest"]:
                            connection.execute("COMMIT")
                            return
                        raise PolicyRegistryError("registry release was equivocated")
                    if snapshot.release < prior_release:
                        raise PolicyRegistryError("registry rollback rejected")
                    prior_states = self._decode_profile_states(
                        row["profile_states_json"]
                    )
                    for profile_id, prior_state in prior_states.items():
                        current_state = states.get(profile_id)
                        if current_state is None:
                            raise PolicyRegistryError(
                                "registry cannot remove a historical profile"
                            )
                        prior_status = prior_state["status"]
                        current_status = current_state["status"]
                        if current_status not in _TRANSITIONS[prior_status]:
                            raise PolicyRegistryError(
                                f"invalid profile transition for {profile_id}"
                            )
                        prior_changed = prior_state["status_changed_at"]
                        current_changed = current_state["status_changed_at"]
                        if current_status == prior_status and current_changed != prior_changed:
                            raise PolicyRegistryError(
                                f"unchanged profile rewrote transition time for {profile_id}"
                            )
                        if current_status != prior_status and current_changed <= prior_changed:
                            raise PolicyRegistryError(
                                f"profile transition time did not advance for {profile_id}"
                            )
                    for profile_id in states.keys() - prior_states.keys():
                        if states[profile_id]["status"] != "active":
                            raise PolicyRegistryError(
                                "new registry profile must begin active"
                            )
                connection.execute(
                    """
                    INSERT INTO policy_registry_state(
                        singleton, release, digest, profile_states_json, accepted_at
                    ) VALUES (1, ?, ?, ?, ?)
                    ON CONFLICT(singleton) DO UPDATE SET
                        release=excluded.release,
                        digest=excluded.digest,
                        profile_states_json=excluded.profile_states_json,
                        accepted_at=excluded.accepted_at
                    """,
                    (
                        snapshot.release,
                        snapshot.digest,
                        canonical_json(states).decode("ascii"),
                        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    ),
                )
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")
