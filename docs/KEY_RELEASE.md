# Attestation-gated data-key release

Cathedral defines a disabled-by-default protocol for releasing an encrypted
per-workload data key only to a fresh, policy-approved CPU worker. This is a
control-plane and broker contract. No production broker or customer container
execution path is enabled by this repository today.

## Required bindings

A grant is issued only when all of the following agree:

- an HMAC-authenticated allocator assignment names the exact admitted workload,
  customer issuer, worker hotkey, purpose, and opaque data-key reference;
- production release accepts only an assignment whose signed capability says
  it was minted by a preflighted production admission controller and verifier;
- the workload carries an enforced admission capability from the immutable
  signed-image policy;
- the worker lifecycle is `attested`, inside its exact evidence-expiry window,
  and no more than 60 seconds old;
- the current signed attestation policy release and digest still match;
- the exact verifier-policy digest, including TCB, firmware, status, and
  advisory constraints, still matches the evidence lifecycle;
- the complete key-release policy digest, including allowed purposes and all
  freshness, TTL, and skew limits, is unchanged;
- hardware, software, and channel assurance claims are all `passed`; and
- a 32-byte X25519 application public key has the exact
  `application_key_sha256` digest bound into that fresh attestation.

The channel claim must byte-for-byte match the verifier-owned assurance record
already persisted for that worker. A caller-created `Attested` object cannot
replace that record or introduce a different application key.

The production/development admission environment is itself inside the workload
capability HMAC. Admission controller mode, verifier, policy, and capability
key are immutable after construction, and the external verifier's executable,
timeout, and output-bound configuration cannot be replaced after preflight.
The immutability checks use fixed field sets that instance attributes cannot
shadow. Production validation rejects an older development capability even if
it was otherwise marked `enforced`.

TLS ownership alone is not sufficient for data-key release. A different
application key, workload manifest, worker, policy, purpose, issuer, or custody
reference cannot reuse the grant.

Grant TTL is policy-controlled and cannot exceed 60 seconds or the remaining
assignment, hardware, and channel attestation-freshness windows. Because expiry
is exclusive, evidence already 60 seconds old has no remaining release window.
The exact expiry instant is denied and assignment validity, freshness, policy,
and lifecycle state are rechecked immediately before ciphertext returns.

## Broker boundary

The provider-neutral broker receives a grant ID as its idempotency key, the
opaque custody reference, the attested application public key, and hashes of
all other release inputs. Its response is an encrypted envelope, never a
plaintext key.

The local test broker uses X25519, HKDF-SHA-256, and AES-256-GCM. The complete
immutable grant digest is part of the authenticated data. The ephemeral public
key, nonce, ciphertext, algorithm, and exact broker-request digest are persisted
as canonical bytes.

Production mode rejects the local broker. A production-capable adapter must
keep root unwrap capability outside the registry database and outside the
validator data-store process. It must durably implement grant-ID idempotency:
after returning a ciphertext once, retries for the same request return the same
bytes even if Cathedral crashed before local persistence. A different request
under the same grant ID must fail.

Startup also requires a pinned broker-configuration digest and a structured
preflight result declaring an external KMS or separately attested custody
boundary, ciphertext-only responses, durable idempotency, and full request
binding. Missing, malformed, false, or differently pinned assertions fail
closed. The enabled flag, production mode, broker adapter, and pinned digest
are read-only after construction, so enabling or swapping custody requires a
fresh startup and preflight. Direct mutation of the corresponding internal
configuration fields is also rejected. These assertions are the adapter
contract; deployment acceptance must independently verify that the configured
endpoint and custody architecture are truthful before enabling the feature.

## Redemption state machine

Redemption is `issued -> redeeming -> redeemed`:

1. Cathedral verifies assignment ownership, channel key, expiry, current
   lifecycle, and active policies.
2. It durably records `redeeming` before calling the broker.
3. The broker returns its idempotent ciphertext.
4. Cathedral rechecks lifecycle, policy, and expiry, then atomically persists
   the exact envelope and the `redeemed` audit transition.
5. A final current-state check is the release decision point before ciphertext
   is returned. The clock is sampled again after policy and registry reads, so
   a slow check cannot carry ciphertext across the deadline. A backward wall-
   clock step fails closed until time catches up. Sampling itself occurs under
   the ordering lock so concurrent forward-moving requests are not mistaken for
   rollback. Registry lifecycle clocks are sampled only after SQLite obtains
   the write-ordering transaction, which extends that ordering across separate
   registry processes sharing the database.

Registry initialization takes the same SQLite write-ordering transaction before
schema backfill consumes a lifecycle timestamp, so concurrently starting
processes cannot race the persisted clock high-water mark.

Retries before the broker response continue the same grant. Retries after the
response but before local persistence ask the broker for the same idempotency
key. Retries after persistence return the same stored ciphertext without a new
unwrap, but only after the same final expiry, assignment, policy, and lifecycle
check. Concurrent same-channel requests converge on the same bytes; a different
channel is rejected before broker access.

Revocation or expiry stops a new release or ciphertext reissue. It cannot claw
back plaintext already decrypted inside a running workload.

Issuing the same assignment with any changed immutable grant binding,
including issue or expiry time, fails as a conflict; it never returns a
previous grant with a longer lifetime than the new request.

## Persistence and disclosure

SQLite stores grant metadata, keyed issuer and custody pseudonyms, one-way
measurement and channel digests, append-only transition events, and encrypted
envelope bytes. The keyed pseudonyms resist offline enumeration from a database
copy because their HMAC key remains in the assignment-authority boundary. It does
not store the customer issuer string, custody reference, application public
key, plaintext data key, broker credential, or root unwrap material.

The customer-safe grant view exposes state, assignment, worker, manifest,
purpose, and validity times. Evidence, policy, channel, custody, issuer, event,
and envelope digests remain operator-only. Broker and provider exception text
is never copied into customer-visible errors.

Mutable plaintext buffers are zeroed where the local test implementation can
control them. Python and the cryptography backend may retain internal immutable
copies, so production plaintext handling belongs inside the external custody
boundary rather than this process.
