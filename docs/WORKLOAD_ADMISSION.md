# Signed workload admission

Cathedral has a provider-neutral contract for admitting future customer
workloads by immutable image digest. This contract is CPU-first control-plane
infrastructure. It does **not** mean that customer container execution is live
or scored today.

## Admission boundary

A production request names only:

- an OCI image in `registry/repository@sha256:<digest>` form;
- the required signer identity;
- digests of arguments, configuration, and optional customer artifacts; and
- approved resource and runtime profiles.

Tags, credentials, transport prefixes, local registries, IP literals, path
traversal, alternate digest algorithms, queries, and fragments are rejected.
Cathedral never resolves a tag and therefore cannot silently execute bytes that
changed after admission.

The admission policy fixes the allowed registries, signer identities, verifier
trust roots, resource profiles, and runtime profiles. Its canonical digest is
embedded in each admitted manifest.

Production admission also requires default service credentials, privileged
mode, host networking, and host integration to remain disabled. General
network policy belongs to the selected runtime profile; `host_network` means
joining the host namespace and is always denied.

## Signature verifier protocol

Production signature verification runs in a separate process with `shell=False`,
an absolute credential-free argument vector, a deadline, and a combined stdout
and stderr byte limit. Credentials belong in the service environment or the
provider identity mechanism, never command arguments. Output is canonical JSON
with an exact schema; unknown fields, duplicate keys, malformed JSON, a nonzero
exit, timeout, oversized output, missing trust root, wrong signer, or a verdict
for another digest all fail closed.

Startup preflight requires the verifier to confirm protocol version 1 and the
exact configured trust-root set. Production admission refuses the development
verifier.

## Immutable manifest

Successful verification produces `cathedral_workload_manifest_v1`, containing:

- the exact image reference and digest;
- registry and repository;
- signer, signature, and trust-root identities;
- admission policy ID and digest;
- argument, configuration, and artifact digests; and
- resource and runtime profiles.

The canonical manifest digest is the typed integration value for future key
release and public receipts. Those integrations must use this digest whenever
sealed customer workloads are enabled; placeholders or mutable references are
not allowed.

## Execution adapter

Admission mints an in-process HMAC capability over the exact manifest. The
provider-neutral dispatcher validates that capability before invoking an
execution adapter and requires the adapter to echo the same manifest digest and
opaque execution ID. The included recording adapter performs no process or CVM
execution; it exists for safe development and integration tests and is rejected
by a production controller.

The external execution adapter is the production bridge to a separately
supervised, provider-owned CVM host agent. It uses a timeout-, input-, and
output-bounded canonical JSON protocol over a Unix domain socket; it never
spawns a per-request provider subprocess. The socket path, parent directory,
owner, permissions, and inode are checked around each connection, with peer
credentials checked where the operating system exposes them. Startup fails
closed unless the provider echoes the configuration commitment derived from the
socket path, state namespace, peer UID, authorization-key digest, worker,
profiles, and protocol bounds; echoes the worker identity and exact supported
profiles; and asserts all of the following:

- immutable-manifest execution and exact manifest binding;
- provider-side execution-authorization verification;
- durable execution-ID idempotency;
- no default service credentials;
- no host integration or host networking; and
- no privileged mode.

Each request contains the complete canonical admitted manifest, its digest, and
an opaque `assignment-...` or `execution-...` idempotency key. The short-lived
execution permit is sent so the host agent can independently verify its HMAC,
expiry, and exact request bindings. The admission HMAC, customer identity,
custody reference, execution-authority key, and provider credentials are never
sent. Provider results must bind the same execution ID and manifest digest and
return a bounded provider job ID plus a receipt digest. Missing or forged
permits and mismatched, malformed, timed-out, oversized, or non-canonical
results fail closed.

Before provider invocation, a mode-`0600` SQLite journal commits each execution
ID's binding to the exact canonical request. A short lease serializes concurrent
local dispatchers without holding a database transaction across the provider
call. Failed calls retain the immutable binding but release the lease for a
same-request retry; restarts return the persisted result or reject conflicting
reuse. The journal and its parent are owner- and permission-checked, and
symlinks and non-regular files are rejected. The host agent must independently
implement durable idempotency as declared in preflight because a timeout can
make provider acceptance unknowable; every retry carries the same bound ID.

For sealed workloads, `WorkloadAssignmentAuthority.dispatch_execution` first
revalidates the authenticated assignment using its own rollback-detecting clock,
then checks expiry, worker identity, manifest, policy, production provenance,
and the pinned provider configuration. It mints a maximum-30-second HMAC permit
bound to those exact values. The adapter independently verifies that permit and
its own rollback-detecting clock before touching durable state or the provider.
The opaque assignment ID becomes the provider idempotency key. This prevents a
valid assignment from dispatching a different image, crossing workers or
provider configurations, or being replayed through an internal adapter call.
The adapter persists an HMAC-protected wall-clock high-water mark in the same
owner-only state namespace before checking permit expiry. A process restart
therefore cannot make an already observed earlier time acceptable after clock
rollback. Recovery from a legitimately incorrect future clock requires an
explicit operator repair of the protected state; it never silently lowers the
high-water mark.

Audit-only evaluation returns `would_admit` or a typed denial and never returns
an executable capability. A development bypass is explicit, warning-logged,
capability-bound, and unavailable in production mode.

## Security boundary

This layer proves that policy admitted a signed, immutable software artifact.
It does not prove application correctness or output correctness. External
signature infrastructure and its pinned trust roots remain part of the stated
trust boundary. The external execution provider and its pinned configuration
are also an explicit trust boundary: preflight assertions do not independently
prove that a provider implemented them correctly. Customer CVM rentals remain
disabled until a real host agent is deployed on attested hardware and live
acceptance covers launch, attestation-bound access, teardown, idempotent retry,
and receipt retrieval.

This adapter does not turn the scoring worker into a general shell. Cathedral's
rental unit remains an isolated confidential VM; customer software runs inside
that VM, while the SAT lane remains a separate validator-verifiable scoring
canary.
