# Assurance receipts

Cathedral assurance receipts are small, signed records for one worker and one
validator-issued work challenge. They preserve the exact assurance result at
the time it was produced without publishing raw attestation evidence, customer
payloads, credentials, endpoints, or a reusable physical-machine identifier.

A receipt is evidence for the claims it contains. It is not a general promise
that an application is bug-free, that arbitrary output is correct, or that a
customer handled its own keys securely. The signed epoch score vector remains
the accounting source used by score-stream consumers; receipts do not replace
or change that contract.

## What each claim means

| Claim | `passed` means | It does not mean |
|---|---|---|
| `hardware` | Fresh vendor-backed evidence identified an accepted confidential CPU and security state. | The approved Cathedral software ran or produced correct work. |
| `software` | The measured software matched the named signed policy snapshot. | The result was correct or the connection was protected. |
| `channel` | The live worker endpoint controlled the channel key bound into the attestation evidence. | The application result was correct. |
| `work` | The named challenge result passed the validator's lane-specific verification. | Every possible output or external side effect was correct. |

Statuses are `not_evaluated`, `passed`, `failed`, `stale`, or `revoked`.
Every evaluated claim has an evidence digest, policy digest, canonical UTC
verification time, and a safe reason category when it did not pass.
`not_evaluated` has `null` for all four audit fields. There is deliberately no
single overall-verification flag.

## Version 1 schema

The schema identifier is `cathedral_assurance_receipt_v1`.

| Field | Meaning |
|---|---|
| `receipt_id` | SHA-256 identifier of the canonical body before `receipt_id` and `signature` are added. |
| `epoch_id`, `source_epoch` | Local immutable epoch row and external source epoch. |
| `subject_hotkey` | Worker identity to which the challenge was assigned. |
| `platform_pseudonym` | Source-epoch-scoped SHA-256 pseudonym; not the raw hardware identity. |
| `policy_registry_release`, `policy_registry_digest` | Exact signed registry snapshot used for admission. |
| `policy_profile_ids` | Exact active CPU profiles selected from that snapshot. |
| `measurement` | Approved software measurement returned by attestation verification. |
| `tcb` | Vendor TCB audit version, exact SVN, status, advisory IDs, debug state, and collateral-current result. Strict TDX receipts enforce the registry status/advisory policy and require a canonical SVN, debug disabled, and current collateral. Raw TDX SVN is recorded for audit and is not treated as a scalar ordering rule. |
| `channel` | Channel claim status and its evidence digest. |
| `work` | Claim status, challenge ID, canonical workload-manifest digest, result digest, and decimal work units. Non-passing work always records `"0"`; passed work can still receive zero credit when a separate eligibility claim is unsatisfied. |
| `assurance` | The four independent typed claims and their component digests. |
| `lifecycle` | Receipt state. Version 1 accepts only `issued` with a `null` revocation reference. |
| `issued_at` | UTC issuance time with exactly six fractional digits. |
| `signing_key_id`, `signature` | Registry-anchored Ed25519 key and signature over all other receipt fields. |

Unknown or missing fields fail closed. A new critical field or lifecycle state
requires a new schema version; version 1 verifiers do not silently ignore it.

## Canonical bytes and durable storage

Receipts use JSON with keys sorted, ASCII escaping enabled, separators `,` and
`:` and no insignificant whitespace. Floating-point JSON, duplicate keys,
non-finite numbers, out-of-range integers, noncanonical timestamps, excessive
nesting, and documents over 256 KiB are rejected. Work units are decimal
strings so values such as zero have one representation.

The runtime signs one receipt after every dispatched challenge, including a
failed result with explicit zero credit. Challenge resolution and insertion of
the exact receipt bytes happen in one SQLite transaction. A crash therefore
leaves both present or leaves the challenge unresolved with no receipt. Stored
receipts are returned as their original bytes and are never reconstructed from
later mutable state.

The repository's deterministic golden receipt is
[`tests/fixtures/assurance-receipt-v1.json`](../tests/fixtures/assurance-receipt-v1.json).
Its keys and measurements are test-only.

## Offline verification

Verification needs two trust inputs:

1. the historical signed policy registry whose release and digest are named in
   the receipt; and
2. a locally pinned registry trust root.

For compromise-aware verification, also supply the newest authenticated
registry available. It carries the current receipt-key retirement or
revocation state. Omitting it verifies against the historical snapshot only
and cannot discover a later compromise declaration.

```bash
cathedral receipt verify \
  --receipt receipt.json \
  --policy-registry historical-registry.json \
  --trusted-keys trusted-policy-keys.json \
  --key-registry current-registry.json
```

Success and failure are JSON. Failures use stable categories: `schema`,
`policy`, `key`, `signature`, `lifecycle`, or `policy_registry`. Verification
checks the exact registry release/digest, eligible profiles and measurement,
claim timestamps and policy digests, work/channel consistency, receipt ID,
signing-key state, and Ed25519 signature.

## Receipt-signing key lifecycle

Receipt public keys are entries in the signed policy registry. Each entry fixes
its key ID, Ed25519 public key, `assurance_receipt` purpose, validity window,
state, transition time, optional replacement, and metadata. A key ID can never
change public-key bytes across releases, and a published key cannot disappear.

| Key state | Verification behavior |
|---|---|
| `active` | May sign and verify receipts inside its validity window. |
| `retired` | Cannot sign; receipts issued before the retirement time still verify. |
| `revoked` | All receipts using the key fail verification. Use for suspected key compromise. |

Normal rotation publishes old and replacement keys together, moves the old key
to `retired`, and keeps both historical records. Compromise recovery moves the
old key to `revoked`; it intentionally invalidates earlier signatures because
the verifier can no longer know which were produced by the legitimate holder.
Registry rollback, same-release equivocation, key deletion, key-material
replacement, reactivation, and future-dated transitions are rejected.

The signing seed is a 32-byte value stored as base64 in a regular non-symlink
file. In production the file must be owned by the runtime user and must not be
group- or world-accessible. Configure
both `--receipt-signing-key-id` and `--receipt-signing-key-file`; issuance is
available only when the runtime is also using the signed policy registry.

## Privacy and retention

The public receipt includes the hotkey, source-epoch-scoped platform
pseudonym, measurements, bounded TCB facts, and cryptographic digests. It does
not include raw quotes, certificate chains, bearer tokens, customer data or
data keys, private endpoints, or the operator's stable physical-machine ID.
The pseudonym changes with `source_epoch`, limiting cross-epoch hardware
linkability; the public hotkey remains intentionally linkable.

Operator-only evidence may be retained under separate access controls for
incident response. It is not required to verify the public signature and must
not be copied into the public receipt. Cathedral performs no automatic receipt
deletion: operators must retain exact receipt bytes plus the referenced policy
registries and trust roots for the promised audit period. Deleting any of
those inputs makes later independent verification incomplete.

Rollback disables new issuance but preserves all existing bytes, historical
registries, and verification keys. Publishing receipts can therefore be rolled
back without changing scoring or rewriting history.

If the policy registry or receipt key expires while an epoch is running,
issuance fails closed and the epoch attempt is aborted without a partial
challenge/receipt commit. Operators must load a fresh registry and retry.
