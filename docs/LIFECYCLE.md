# Worker attestation lifecycle

Cathedral tracks every enrolled confidential CPU worker through an explicit,
durable lifecycle. A reachable endpoint is not enough: positive eligibility
requires fresh accepted attestation evidence for the current measurement
policy.

## States

| State | Meaning | Network refresh | Score eligibility |
|---|---|---:|---:|
| `pending` | Enrolled or explicitly reenrolled, but not yet attested. | Yes, when its retry is due. | No |
| `attested` | The latest accepted evidence is still inside its freshness window. | Yes, before expiry or when a retry is due. | Yes, subject to work verification. |
| `stale` | Evidence reached its exact expiry boundary without a successful refresh. | Yes, with bounded retry. | No |
| `failed` | The configured refresh-attempt bound was exhausted or verification failed terminally. | No | No |
| `retiring` | An operator is stopping the worker. | No | No |
| `retired` | The worker was stopped and retained only for audit. | No | No |
| `revoked` | Policy or identity rules invalidated the worker. | No | No |

`failed`, `retired`, and `revoked` do not resume automatically. Recovery
requires explicit reenrollment, which creates a new generation in `pending`;
it never rewrites the old history. Identity conflicts remain terminal for the
generation in which they were detected.

## Freshness and retries

Freshness is calculated from the attestation verification time plus the
configured verification TTL. The exact expiry instant is ineligible: evidence
is fresh only while `now < evidence_expires_at`.

Only one refresh operation may run for a worker generation at a time. Failures
use deterministic bounded exponential backoff and bounded jitter. The retry
count and next retry time are stored in SQLite, so a process restart does not
reset or multiply retries. The default runtime policy is three failed refresh
cycles with a 5-second base, 300-second maximum, and up to 5 seconds of jitter.

A transport failure cannot extend evidence validity. If an earlier attestation
is still fresh, a retry may remain scheduled until that evidence expires. At
expiry the worker becomes `stale` and receives zero. Exhausting the attempt
bound moves it to `failed`.

Runtime controls:

```text
--reattestation-failures-before-failed 3
--reattestation-retry-base-seconds 5
--reattestation-retry-maximum-seconds 300
--reattestation-retry-jitter-seconds 5
```

## Policy and concurrency safety

A measurement removed from the active policy moves directly to `revoked`
without contacting the worker. Identity conflicts do the same. Terminal
transitions cancel local refresh work; generation and revision checks discard
late results from another thread or process before they can restore eligibility.

Each state change appends an event and updates the current projection in one
database transaction. Clock rollback, an illegal transition, or a stale
generation/revision fails closed and leaves both records unchanged.

Every completed epoch includes the state, reason, generation, revision, event
ID, evidence-expiry time, and snapshot time used for score gating. Receipt v2
signs the same lifecycle identifiers and expiry. When a receipt exists, the
ledger rejects an epoch snapshot that does not match those signed fields.

## Public and operator views

The customer-safe view contains the state, safe reason, generation, transition
time, verification time, and evidence expiry. It omits endpoint URLs, raw
evidence, stable machine identifiers, detailed failures, retry internals, and
policy/evidence digests.

```bash
cathedral lifecycle status \
  --registry-db cathedral-enroll.sqlite \
  --hotkey WORKER_HOTKEY

cathedral lifecycle history \
  --registry-db cathedral-enroll.sqlite \
  --hotkey WORKER_HOTKEY

cathedral lifecycle reenroll \
  --registry-db cathedral-enroll.sqlite \
  --hotkey WORKER_HOTKEY

cathedral lifecycle retire \
  --registry-db cathedral-enroll.sqlite \
  --hotkey WORKER_HOTKEY \
  --removed
```

Operators may add `--operator` to either command to see event identifiers,
measurement and digest references, retry metadata, and bounded failure detail.
Operator output should remain access-controlled and must not be copied into a
public status response.

Reenrollment is the explicit recovery mechanism after a terminal failure or
revocation. It clears the current generation's evidence and retry fields and
starts a new `pending` generation without modifying prior events. `retire`
stops network refresh and score eligibility in `retiring`; add `--removed` once
the worker has been removed to finish in `retired`. Runtime-driven retirement
also cancels local in-flight work. A late result from another process loses the
generation/revision comparison and cannot restore eligibility.

## Upgrade and rollback

Existing enrollment rows are backfilled conservatively. Rows without enough
typed evidence to prove current eligibility do not gain positive credit from
the migration. Rollback may pause automated refresh execution, but expired,
failed, retired, or revoked state must remain ineligible. Rollback must retain
the append-only event history, frozen epoch reports, exact receipt bytes, and
the policy snapshots needed to verify them.
