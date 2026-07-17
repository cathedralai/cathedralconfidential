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
execution adapter and requires the adapter to echo the same manifest digest.
The included recording adapter performs no process or container execution; it
exists for safe integration tests.

Audit-only evaluation returns `would_admit` or a typed denial and never returns
an executable capability. A development bypass is explicit, warning-logged,
capability-bound, and unavailable in production mode.

## Security boundary

This layer proves that policy admitted a signed, immutable software artifact.
It does not prove application correctness or output correctness. External
signature infrastructure and its pinned trust roots remain part of the stated
trust boundary. Customer execution stays disabled until a real provider
adapter, attestation-gated key release, and live acceptance evidence exist.
