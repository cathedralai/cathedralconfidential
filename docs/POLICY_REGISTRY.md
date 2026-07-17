# Signed policy registry

Cathedral policy registries are public, immutable Ed25519-signed artifacts.
They identify software measurements and hardware-security profiles accepted for
new admissions during a defined UTC window. A listed measurement means that a
software configuration is approved; it does not mean that customer work was
correct or successful.

The current runtime consumer is deliberately CPU-first: it constructs strict
Intel TDX admission policy from eligible `cpu_tdx` profiles. The versioned
schema can preserve CPU SNP, runtime-measurement, and GPU profile material for
future consumers, but those fields do not yet make those lanes admission-
eligible. A registry with no usable CPU TDX profile is rejected before the
validator advances its durable release checkpoint.

## Verification contract

The schema identifier is `cathedral_policy_registry_v1`. The signed bytes are
the registry object with the top-level `signature` member removed, serialized
as UTF-8 JSON with keys sorted, ASCII escaping enabled, and separators `,` and
`:` with no extra whitespace. Duplicate keys, floating-point numbers, unknown
critical fields, noncanonical UTC timestamps, and unknown schema versions are
rejected before use. Encoded size, profile count, policy-list size, and metadata
depth/complexity are bounded before the document becomes runtime policy.

The signature object is:

```json
{"algorithm":"ed25519","value_base64":"<64-byte signature>"}
```

The `signing_key_id` selects one locally pinned 32-byte Ed25519 public key.
Keys are configuration, not registry content: a registry cannot introduce the
key that authorizes itself. Rotation uses a bounded overlap in which operators
pin the new key before a release signed by it is accepted, then remove the old
key after all validators have crossed the announced checkpoint.

Run the customer-safe verifier:

```bash
cathedral policy-registry verify \
  --registry examples/policy-registry/registry-v1.json \
  --trusted-keys examples/policy-registry/trusted-keys.json \
  --historical-at 2026-07-17T12:00:00Z
```

`--historical-at` is inspection-only and never updates admission state. Omit it
for current admission-policy checks, which enforce freshness and current time.

## Registry and profile lifecycle

Every registry has a positive monotonically increasing `release`,
`generated_at`, `valid_from`, and exclusive `valid_until`. Admission requires
the signature, the current validity window, and a configurable maximum age.
A signed but stale release is not current admission policy.

Profiles are never deleted after publication. Their states are:

| State | Admission meaning |
|---|---|
| `active` | Accepted inside the profile and registry validity windows. |
| `retiring` | Accepted only until the explicit `retire_at` boundary. |
| `retired` | Preserved for audit; not accepted for new admission. |
| `revoked` | Immediately excluded from new admission. |

Allowed transitions are `active → retiring → retired`, with revocation allowed
from active or retiring. Retired and revoked profiles cannot be reactivated.
Overlapping active and retiring CPU profiles must use identical minimum TCB,
TCB-status, advisory, and firmware controls; overlap cannot silently weaken the
security floor.

## Rollback and bootstrap

Validators persist the last accepted release, digest, and profile states in a
separate SQLite state file. A lower release, same-release different digest, a
removed historical profile, or an invalid state transition fails closed.

A fresh production state store is not an empty trust decision. Operators must
configure either an exact signed checkpoint or a positive minimum release. The
minimum must move forward with operational rollouts so restoration of an old
backup or loss of the state file cannot reopen an obsolete signed release.
The local high-water mark cannot prove that a distributor has not withheld a
newer release; bounded document age and an operator-managed minimum release are
the fail-closed controls until an authenticated release-discovery channel is
introduced.

The runtime exposes both bootstrap forms: use
`--policy-registry-min-release`, or supply the exact pair
`--policy-registry-pinned-release` and `--policy-registry-pinned-digest`.

## Epoch and historical verification

One verified registry snapshot is converted to an immutable `Policy` before an
epoch begins. The epoch report records the exact registry release and SHA-256
digest; a mutable file cannot change policy midway through the epoch.

Historical receipt verification may load an older signed registry only when
the receipt time falls inside that registry's validity window. That historical
check does not update the admission high-water mark and never makes the old
release current again.

The committed sample contains placeholders only. Its deterministic test key is
intentionally reproducible and must never be configured as a production trust
root. It contains no production measurement, endpoint, platform identifier, or
production signing material.
