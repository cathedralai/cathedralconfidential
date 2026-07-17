"""Canonical, signed, privacy-bounded assurance receipts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.assurance import (
    ASSURANCE_SCHEMA,
    AssuranceClaims,
    AssuranceDimension,
    ClaimStatus,
    CHANNEL_BINDING_POLICY_DIGEST,
    assurance_from_dict,
    policy_digest,
    sha256_digest,
)
from cathedral.common import Attested, Policy
from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistrySnapshot,
    canonical_json,
)


RECEIPT_SCHEMA = "cathedral_assurance_receipt_v1"
MAX_RECEIPT_BYTES = 256 * 1024
MAX_SQLITE_INTEGER = 2**63 - 1
MAX_TCB_ADVISORIES = 256
MAX_RECEIPT_DEPTH = 32
MAX_RECEIPT_NODES = 4096
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECEIPT_ID_RE = re.compile(r"^receipt-sha256:[0-9a-f]{64}$")
_PLATFORM_RE = re.compile(r"^platform-sha256:[0-9a-f]{64}$")
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")
_TCB_SVN_RE = re.compile(r"^[0-9a-f]{32}$")
_DECIMAL_RE = re.compile(r"^(?:0|[1-9]\d*)(?:\.\d*[1-9])?$")
_TOP_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "epoch_id",
        "source_epoch",
        "subject_hotkey",
        "platform_pseudonym",
        "policy_registry_release",
        "policy_registry_digest",
        "policy_profile_ids",
        "measurement",
        "tcb",
        "channel",
        "work",
        "assurance",
        "lifecycle",
        "issued_at",
        "signing_key_id",
        "signature",
    }
)
_TCB_KEYS = frozenset(
    {
        "status",
        "version",
        "svn",
        "advisory_ids",
        "debug_enabled",
        "collateral_current",
    }
)
_CHANNEL_KEYS = frozenset({"status", "binding_digest"})
_WORK_KEYS = frozenset(
    {"status", "challenge_id", "manifest_digest", "result_digest", "work_units"}
)
_LIFECYCLE_KEYS = frozenset({"state", "revocation_reference"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_ASSURANCE_KEYS = frozenset({"schema", "claims"})
_CLAIM_KEYS = frozenset(
    {"status", "evidence_digest", "policy_digest", "verified_at", "reason"}
)


class ReceiptError(ValueError):
    """Stable receipt verification failure with a machine-readable category."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("schema", f"duplicate receipt JSON key {key!r}")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ReceiptError("schema", "receipt integer is invalid") from exc
    if not -MAX_SQLITE_INTEGER <= parsed <= MAX_SQLITE_INTEGER:
        raise ReceiptError("schema", "receipt integer exceeds the supported range")
    return parsed


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_RECEIPT_NODES or depth > MAX_RECEIPT_DEPTH:
            raise ReceiptError("schema", "receipt JSON structure is too complex")
        if isinstance(current, dict):
            for key in current:
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ReceiptError(
                        "schema", "receipt contains invalid Unicode"
                    ) from exc
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ReceiptError("schema", "receipt contains invalid Unicode") from exc


def parse_receipt_json(data: bytes | str) -> dict[str, object]:
    try:
        encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ReceiptError("schema", "receipt is not UTF-8 JSON") from exc
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ReceiptError("schema", "receipt exceeds the maximum encoded size")
    try:
        parsed = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ReceiptError("schema", "floating-point receipt JSON is unsupported")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ReceiptError("schema", "non-finite receipt JSON is unsupported")
            ),
            parse_int=_json_integer,
        )
    except ReceiptError:
        raise
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as exc:
        raise ReceiptError("schema", "receipt is not UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ReceiptError("schema", "receipt must be a JSON object")
    _validate_json_shape(parsed)
    return parsed


def _timestamp(value: object, label: str = "receipt issued_at") -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ReceiptError("schema", f"{label} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReceiptError("schema", f"{label} must be canonical UTC time") from exc


def _format_time(value: datetime | None = None) -> str:
    when = value or datetime.now(UTC)
    if when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise ReceiptError("schema", "receipt issue time must be UTC")
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _bounded_text(value: object, maximum_bytes: int, *, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum_bytes
    except UnicodeEncodeError:
        return False


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _work_units(value: object) -> str:
    if isinstance(value, bool):
        raise ReceiptError("schema", "receipt work units must be nonnegative")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ReceiptError("schema", "receipt work units must be nonnegative") from exc
    if not number.is_finite() or number < 0:
        raise ReceiptError("schema", "receipt work units must be nonnegative")
    encoded = format(number, "f")
    if "." in encoded:
        encoded = encoded.rstrip("0").rstrip(".")
    if encoded in {"", "-0"}:
        encoded = "0"
    if len(encoded) > 64 or _DECIMAL_RE.fullmatch(encoded) is None:
        raise ReceiptError("schema", "receipt work units are not canonical decimal")
    return encoded


def _strict_assurance(raw: object) -> AssuranceClaims:
    if not isinstance(raw, dict) or frozenset(raw) != _ASSURANCE_KEYS:
        raise ReceiptError("schema", "receipt assurance object is invalid")
    if raw["schema"] != ASSURANCE_SCHEMA or not isinstance(raw["claims"], dict):
        raise ReceiptError("schema", "receipt assurance schema is invalid")
    claims = raw["claims"]
    assert isinstance(claims, dict)
    if frozenset(claims) != {dimension.value for dimension in AssuranceDimension}:
        raise ReceiptError("schema", "receipt must contain all assurance dimensions")
    if any(
        not isinstance(claim, dict) or frozenset(claim) != _CLAIM_KEYS
        for claim in claims.values()
    ):
        raise ReceiptError("schema", "receipt assurance claim fields are invalid")
    try:
        return assurance_from_dict(raw)
    except ValueError as exc:
        raise ReceiptError("schema", "receipt assurance claims are invalid") from exc


def _validate_claim_times_and_policy(
    claims: AssuranceClaims,
    issued_at: datetime,
    expected_policy_digest: str,
) -> None:
    for dimension in AssuranceDimension:
        claim = claims.claim(dimension)
        if claim.status is ClaimStatus.NOT_EVALUATED:
            continue
        verified_at = _timestamp(
            claim.verified_at,
            f"receipt {dimension.value} claim verified_at",
        )
        if verified_at > issued_at:
            raise ReceiptError(
                "schema",
                f"receipt {dimension.value} claim is later than receipt issuance",
            )
    for dimension in (AssuranceDimension.HARDWARE, AssuranceDimension.SOFTWARE):
        claim = claims.claim(dimension)
        if (
            claim.status is not ClaimStatus.NOT_EVALUATED
            and claim.policy_digest != expected_policy_digest
        ):
            raise ReceiptError(
                "policy",
                f"receipt {dimension.value} claim does not match registry policy",
            )
    if (
        claims.channel.status is not ClaimStatus.NOT_EVALUATED
        and claims.channel.policy_digest != CHANNEL_BINDING_POLICY_DIGEST
    ):
        raise ReceiptError("policy", "receipt channel claim policy is unsupported")


def _id_material(document: Mapping[str, object]) -> bytes:
    material = dict(document)
    material.pop("receipt_id", None)
    material.pop("signature", None)
    try:
        return canonical_json(material)
    except PolicyRegistryError as exc:
        raise ReceiptError("schema", "receipt contains a non-canonical value") from exc


def _unsigned_bytes(document: Mapping[str, object]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    try:
        return canonical_json(unsigned)
    except PolicyRegistryError as exc:
        raise ReceiptError("schema", "receipt contains a non-canonical value") from exc


def _platform_pseudonym(chip_id: str, source_epoch: int) -> str:
    material = (
        b"cathedral.public-platform-pseudonym.v1\x00"
        + str(source_epoch).encode("ascii")
        + b"\x00"
        + chip_id.encode("utf-8")
    )
    return "platform-sha256:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class AssuranceReceipt:
    receipt_id: str
    receipt_bytes: bytes
    receipt_digest: str
    document: Mapping[str, object]


class ReceiptIssuer:
    """Issue receipts with a registry-anchored Ed25519 key."""

    def __init__(
        self,
        registry: PolicyRegistrySnapshot,
        signing_key_id: str,
        private_key_seed: bytes,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
            raise ReceiptError("key", "receipt private key seed must be 32 bytes")
        key = registry.receipt_key(signing_key_id)
        if key is None:
            raise ReceiptError("key", "receipt signing key is absent from the registry")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
        public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if public != key.public_key:
            raise ReceiptError("key", "receipt private key does not match the registry")
        if not callable(clock):
            raise ReceiptError("schema", "receipt clock must be callable")
        self.registry = registry
        self.signing_key_id = signing_key_id
        self._private_key = private_key
        self._clock = clock

    def issue(
        self,
        *,
        epoch_id: int,
        source_epoch: int,
        subject_hotkey: str,
        attested: Attested,
        policy: Policy,
        assurance: AssuranceClaims,
        challenge_id: str | None,
        manifest_digest: str | None,
        work_units: float,
        issued_at: datetime | None = None,
    ) -> AssuranceReceipt:
        when_text = _format_time(issued_at if issued_at is not None else self._clock())
        when = _timestamp(when_text)
        key = self.registry.receipt_key(self.signing_key_id)
        assert key is not None
        if not key.can_sign_at(when):
            raise ReceiptError("key", "receipt signing key is not active at issue time")
        if not self.registry.valid_from <= when < self.registry.valid_until:
            raise ReceiptError("policy", "receipt issue time is outside registry validity")
        policy_at = _timestamp(
            assurance.hardware.verified_at,
            "receipt hardware claim verified_at",
        )
        try:
            expected_policy = self.registry.to_policy(at=policy_at)
        except PolicyRegistryError as exc:
            raise ReceiptError("policy", "receipt registry has no eligible CPU policy") from exc
        if policy != expected_policy:
            raise ReceiptError("policy", "receipt policy does not match its registry")
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= MAX_SQLITE_INTEGER
            for value in (epoch_id, source_epoch)
        ):
            raise ReceiptError("schema", "receipt epoch identifiers are invalid")
        if not _bounded_text(subject_hotkey, 512):
            raise ReceiptError("schema", "receipt subject hotkey is invalid")
        if (
            not _bounded_text(attested.measurement, 512)
            or attested.measurement not in policy.allowed_measurements
        ):
            raise ReceiptError("schema", "receipt measurement is invalid")
        if not _bounded_text(attested.chip_id, 512):
            raise ReceiptError("schema", "receipt platform identity is invalid")
        if attested.assurance is None or any(
            attested.assurance.claim(dimension) != assurance.claim(dimension)
            for dimension in (
                AssuranceDimension.HARDWARE,
                AssuranceDimension.SOFTWARE,
                AssuranceDimension.CHANNEL,
            )
        ):
            raise ReceiptError(
                "schema", "receipt assurance differs from attested assurance"
            )
        _validate_claim_times_and_policy(assurance, when, policy_digest(policy))
        if (
            isinstance(attested.tcb, bool)
            or not isinstance(attested.tcb, int)
            or not 0 <= attested.tcb <= MAX_SQLITE_INTEGER
            or not _bounded_text(attested.tcb_status, 128, allow_none=True)
            or not _bounded_text(attested.tcb_svn, 256, allow_none=True)
            or not isinstance(attested.advisory_ids, tuple)
            or len(attested.advisory_ids) > MAX_TCB_ADVISORIES
            or any(
                not _bounded_text(value, 128)
                for value in attested.advisory_ids
            )
            or (
                attested.debug_enabled is not None
                and not isinstance(attested.debug_enabled, bool)
            )
            or (
                attested.collateral_current is not None
                and not isinstance(attested.collateral_current, bool)
            )
        ):
            raise ReceiptError("schema", "receipt TCB result is invalid")
        if (
            attested.tcb_status not in policy.tdx_allowed_tcb_statuses
            or not set(attested.advisory_ids).issubset(
                policy.tdx_allowed_advisories
            )
            or not isinstance(attested.tcb_svn, str)
            or _TCB_SVN_RE.fullmatch(attested.tcb_svn) is None
            or attested.debug_enabled is not False
            or attested.collateral_current is not True
        ):
            raise ReceiptError("policy", "receipt TCB result does not satisfy policy")
        channel_claim = assurance.channel
        work_claim = assurance.work
        if work_claim.status is ClaimStatus.NOT_EVALUATED:
            if challenge_id is not None or manifest_digest is not None:
                raise ReceiptError("schema", "unevaluated work must carry null work digests")
        else:
            if (
                not isinstance(challenge_id, str)
                or _CHALLENGE_RE.fullmatch(challenge_id) is None
                or not isinstance(manifest_digest, str)
                or _DIGEST_RE.fullmatch(manifest_digest) is None
            ):
                raise ReceiptError("schema", "evaluated work requires challenge and manifest")
        units = _work_units(work_units)
        if work_claim.status is not ClaimStatus.PASSED and units != "0":
            raise ReceiptError("schema", "non-passing work receipt must record zero units")
        document: dict[str, object] = {
            "schema": RECEIPT_SCHEMA,
            "epoch_id": epoch_id,
            "source_epoch": source_epoch,
            "subject_hotkey": subject_hotkey,
            "platform_pseudonym": _platform_pseudonym(attested.chip_id, source_epoch),
            "policy_registry_release": self.registry.release,
            "policy_registry_digest": self.registry.digest,
            "policy_profile_ids": list(policy.registry_profile_ids),
            "measurement": attested.measurement,
            "tcb": {
                "status": attested.tcb_status,
                "version": attested.tcb,
                "svn": attested.tcb_svn,
                "advisory_ids": list(attested.advisory_ids),
                "debug_enabled": attested.debug_enabled,
                "collateral_current": attested.collateral_current,
            },
            "channel": {
                "status": channel_claim.status.value,
                "binding_digest": channel_claim.evidence_digest,
            },
            "work": {
                "status": work_claim.status.value,
                "challenge_id": challenge_id,
                "manifest_digest": manifest_digest,
                "result_digest": work_claim.evidence_digest,
                "work_units": units,
            },
            "assurance": assurance.to_dict(),
            "lifecycle": {"state": "issued", "revocation_reference": None},
            "issued_at": when_text,
            "signing_key_id": self.signing_key_id,
        }
        receipt_id = "receipt-sha256:" + hashlib.sha256(
            _id_material(document)
        ).hexdigest()
        document["receipt_id"] = receipt_id
        signature = self._private_key.sign(_unsigned_bytes(document))
        document["signature"] = {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        }
        try:
            receipt_bytes = canonical_json(document)
        except PolicyRegistryError as exc:
            raise ReceiptError("schema", "receipt contains a non-canonical value") from exc
        return AssuranceReceipt(
            receipt_id=receipt_id,
            receipt_bytes=receipt_bytes,
            receipt_digest=sha256_digest(receipt_bytes),
            document=MappingProxyType(document),
        )


def verify_receipt(
    data: bytes | str,
    policy_registry: PolicyRegistrySnapshot,
    *,
    key_registry: PolicyRegistrySnapshot | None = None,
) -> AssuranceReceipt:
    document = parse_receipt_json(data)
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    try:
        canonical_input = canonical_json(document)
    except PolicyRegistryError as exc:
        raise ReceiptError("schema", "receipt contains a non-canonical value") from exc
    if encoded != canonical_input:
        raise ReceiptError("schema", "receipt JSON is not canonical")
    if frozenset(document) != _TOP_KEYS or document.get("schema") != RECEIPT_SCHEMA:
        raise ReceiptError("schema", "receipt has missing, unknown, or unsupported fields")
    issued_at = _timestamp(document["issued_at"])
    for name in ("epoch_id", "source_epoch", "policy_registry_release"):
        value = document[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= MAX_SQLITE_INTEGER
        ):
            raise ReceiptError("schema", f"receipt {name} is invalid")
    if document["policy_registry_release"] <= 0:
        raise ReceiptError("schema", "receipt registry release is invalid")
    if (
        document["policy_registry_release"] != policy_registry.release
        or document["policy_registry_digest"] != policy_registry.digest
    ):
        raise ReceiptError("policy", "receipt does not match the supplied policy registry")
    if not policy_registry.valid_from <= issued_at < policy_registry.valid_until:
        raise ReceiptError("policy", "receipt time is outside policy registry validity")
    receipt_id = document["receipt_id"]
    expected_id = "receipt-sha256:" + hashlib.sha256(_id_material(document)).hexdigest()
    if (
        not isinstance(receipt_id, str)
        or _RECEIPT_ID_RE.fullmatch(receipt_id) is None
        or receipt_id != expected_id
    ):
        raise ReceiptError("schema", "receipt id does not match its canonical body")
    hotkey = document["subject_hotkey"]
    if not _bounded_text(hotkey, 512):
        raise ReceiptError("schema", "receipt subject hotkey is invalid")
    if not isinstance(document["platform_pseudonym"], str) or _PLATFORM_RE.fullmatch(
        document["platform_pseudonym"]
    ) is None:
        raise ReceiptError("schema", "receipt platform pseudonym is invalid")
    profile_ids = document["policy_profile_ids"]
    if (
        not isinstance(profile_ids, list)
        or not profile_ids
        or any(not isinstance(profile_id, str) for profile_id in profile_ids)
        or profile_ids != sorted(set(profile_ids))
    ):
        raise ReceiptError("schema", "receipt policy profile ids are invalid")
    known_profiles = {profile.profile_id: profile for profile in policy_registry.profiles}
    if any(profile_id not in known_profiles for profile_id in profile_ids):
        raise ReceiptError("policy", "receipt refers to an unknown policy profile")
    measurement = document["measurement"]
    if not isinstance(measurement, str) or not any(
        measurement in known_profiles[profile_id].measurements
        for profile_id in profile_ids
    ):
        raise ReceiptError("policy", "receipt measurement is not in its policy profiles")
    claims = _strict_assurance(document["assurance"])
    policy_at = _timestamp(
        claims.hardware.verified_at,
        "receipt hardware claim verified_at",
    )
    try:
        receipt_policy = policy_registry.to_policy(at=policy_at)
    except PolicyRegistryError as exc:
        raise ReceiptError("policy", "receipt registry has no eligible CPU policy") from exc
    if tuple(profile_ids) != receipt_policy.registry_profile_ids:
        raise ReceiptError("policy", "receipt profile ids do not match registry policy")
    tcb = document["tcb"]
    if not isinstance(tcb, dict) or frozenset(tcb) != _TCB_KEYS:
        raise ReceiptError("schema", "receipt TCB result is invalid")
    if (
        isinstance(tcb["version"], bool)
        or not isinstance(tcb["version"], int)
        or not 0 <= tcb["version"] <= MAX_SQLITE_INTEGER
        or not _bounded_text(tcb["status"], 128, allow_none=True)
        or not _bounded_text(tcb["svn"], 256, allow_none=True)
        or not isinstance(tcb["advisory_ids"], list)
        or len(tcb["advisory_ids"]) > MAX_TCB_ADVISORIES
        or any(
            not _bounded_text(value, 128)
            for value in tcb["advisory_ids"]
        )
        or (
            tcb["debug_enabled"] is not None
            and not isinstance(tcb["debug_enabled"], bool)
        )
        or (
            tcb["collateral_current"] is not None
            and not isinstance(tcb["collateral_current"], bool)
        )
    ):
        raise ReceiptError("schema", "receipt TCB result is invalid")
    if (
        tcb["status"] not in receipt_policy.tdx_allowed_tcb_statuses
        or not set(tcb["advisory_ids"]).issubset(
            receipt_policy.tdx_allowed_advisories
        )
        or not isinstance(tcb["svn"], str)
        or _TCB_SVN_RE.fullmatch(tcb["svn"]) is None
        or tcb["debug_enabled"] is not False
        or tcb["collateral_current"] is not True
    ):
        raise ReceiptError("policy", "receipt TCB result does not satisfy policy")
    _validate_claim_times_and_policy(
        claims,
        issued_at,
        policy_digest(receipt_policy),
    )
    channel = document["channel"]
    work = document["work"]
    lifecycle = document["lifecycle"]
    if not isinstance(channel, dict) or frozenset(channel) != _CHANNEL_KEYS:
        raise ReceiptError("schema", "receipt channel result is invalid")
    if not isinstance(work, dict) or frozenset(work) != _WORK_KEYS:
        raise ReceiptError("schema", "receipt work result is invalid")
    if not isinstance(lifecycle, dict) or frozenset(lifecycle) != _LIFECYCLE_KEYS:
        raise ReceiptError("schema", "receipt lifecycle is invalid")
    if lifecycle != {"state": "issued", "revocation_reference": None}:
        raise ReceiptError("lifecycle", "receipt lifecycle state is unsupported")
    if (
        channel["status"] != claims.channel.status.value
        or channel["binding_digest"] != claims.channel.evidence_digest
    ):
        raise ReceiptError("schema", "receipt channel result contradicts its claim")
    if (
        work["status"] != claims.work.status.value
        or work["result_digest"] != claims.work.evidence_digest
    ):
        raise ReceiptError("schema", "receipt work result contradicts its claim")
    if not isinstance(work["work_units"], str) or _work_units(
        work["work_units"]
    ) != work["work_units"]:
        raise ReceiptError("schema", "receipt work units are not canonical")
    if claims.work.status is ClaimStatus.NOT_EVALUATED:
        if any(work[name] is not None for name in ("challenge_id", "manifest_digest", "result_digest")):
            raise ReceiptError("schema", "unevaluated work must carry null digests")
    else:
        if (
            not isinstance(work["challenge_id"], str)
            or _CHALLENGE_RE.fullmatch(work["challenge_id"]) is None
            or not isinstance(work["manifest_digest"], str)
            or _DIGEST_RE.fullmatch(work["manifest_digest"]) is None
        ):
            raise ReceiptError("schema", "evaluated work requires canonical digests")
    if claims.work.status is not ClaimStatus.PASSED and work["work_units"] != "0":
        raise ReceiptError("schema", "non-passing work receipt must record zero units")
    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise ReceiptError("schema", "receipt signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise ReceiptError("signature", "receipt signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise ReceiptError("signature", "receipt signature is not canonical base64") from exc
    if (
        len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii")
        != signature["value_base64"]
    ):
        raise ReceiptError("signature", "receipt signature must be 64 bytes")
    key_id = document["signing_key_id"]
    if not isinstance(key_id, str):
        raise ReceiptError("key", "receipt signing key id is invalid")
    policy_key = policy_registry.receipt_key(key_id)
    trust_registry = key_registry or policy_registry
    if trust_registry.release < policy_registry.release:
        raise ReceiptError("key", "receipt key registry predates its policy registry")
    trust_key = trust_registry.receipt_key(key_id)
    if policy_key is None or trust_key is None or policy_key.public_key != trust_key.public_key:
        raise ReceiptError("key", "receipt signing key is not consistently anchored")
    if not trust_key.can_verify_at(issued_at):
        raise ReceiptError("key", "receipt signing key is retired, revoked, or out of window")
    try:
        Ed25519PublicKey.from_public_bytes(trust_key.public_key).verify(
            signature_bytes,
            _unsigned_bytes(document),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ReceiptError("signature", "receipt signature verification failed") from exc
    try:
        receipt_bytes = canonical_json(document)
    except PolicyRegistryError as exc:
        raise ReceiptError("schema", "receipt contains a non-canonical value") from exc
    return AssuranceReceipt(
        receipt_id=receipt_id,
        receipt_bytes=receipt_bytes,
        receipt_digest=sha256_digest(receipt_bytes),
        document=MappingProxyType(document),
    )
