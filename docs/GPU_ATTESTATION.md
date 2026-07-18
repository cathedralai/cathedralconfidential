# Composite confidential-GPU attestation

Status: hardware-free foundation complete; live hardware acceptance and all GPU
scoring remain disabled.

Cathedral treats a confidential GPU as a composite trust boundary. A GPU model
string, a driver report, or an independent CPU quote is not enough. The first
supported profile is one Intel TDX component plus one NVIDIA confidential-GPU
component under the same fresh validator challenge.

## What the composite verdict checks

The validator derives an independent GPU challenge:

```text
sha256("cathedral-gpu-nonce-v1\0" || report_data_v2)
```

`report_data_v2` already binds the original 32-byte nonce, assigned worker
hotkey, channel-binding type, and channel-key digest. Both components must carry
that same nonce, hotkey, report-data version, and channel binding. A mismatch
rejects the whole bundle; it is never downgraded to CPU admission.

The TDX quote follows the existing strict CPU policy. A bounded external NVIDIA
verifier must then confirm vendor evidence and the host-session binding.
Cathedral passes that verifier the raw TDX quote and certificate chain plus a
domain-separated digest covering the exact TDX evidence envelope, v2 report
data, verified platform identity, measurement, TCB, and assurance claims. The
verifier may return success only when vendor-authenticated composite evidence
joins the GPU component to that exact TDX digest. Cathedral requires the exact
digest, measurement, and platform identity back with the strict boolean
`composite_binding_verified: true`. An independently valid GPU report and TDX
quote are therefore insufficient, even when they reuse the same challenge or
channel-key digest.
Cathedral independently hashes the verifier's exact argv, constrained process
environment, native executable, and explicit implementation-artifact manifest
before startup, preflight, and verification. Production GPU verification does
not accept argv extensions, interpreters, shell scripts, inline programs,
launchers, module discovery, or relative code paths. Production requires one
statically linked x86-64 ELF executable with no program interpreter or linked
runtime dependencies. It must be a single, self-contained implementation
artifact: runtime libraries, plugins, and external verifier data files are not
accepted. The executable must be root-owned, and neither it nor any directory
in its resolved path may be writable by group or others. Execution starts with
`/` as its working directory. These constraints
prevent an unprivileged writer from replacing a verified pathname or supplying
code through the current directory. An artifact mutation or mismatch with the
signed policy fails closed; a digest self-reported by the verifier is not
sufficient.

Cathedral selects the GPU profile from a verified, rollback-resistant signed
policy-registry snapshot. The profile must be exactly `active` and currently
valid. Production retains that signature provenance, rechecks the profile and
snapshot validity window before network work, and requires the GPU profile to
match the exact registry release and digest that supplied the TDX policy. Its
registry release and digest become part of the profile digest, so a miner cannot
name a weaker or stale profile. The profile applies:

- exact pseudonymous GPU identity-digest set and device count;
- allowed model family and confidential-computing mode;
- allowed driver and VBIOS versions;
- allowed security state and per-device vendor-verification result;
- allowed TDX measurement; and
- the pinned external-verifier digest.

Every field is required and exact. The external verifier handles raw GPU UUIDs
inside the validator process, while the public signed profile carries
domain-separated SHA-256 identity digests rather than raw device identifiers.
Missing, duplicated, unexpected, partially verified, or unknown values reject
the component. A vendor composite JWT may be carried as an input, but it does
not bypass these checks.

The durable lifecycle measurement is stable across fresh nonces and evidence.
It binds the approved TDX measurement to the exact GPU profile digest, registry
release, and registry digest. Fresh evidence remains in the assurance and audit
digests. A later signed release that changes the profile therefore changes the
lifecycle measurement and is evaluated as a new authority, while routine fresh
attestation under an unchanged authority does not revoke the worker.

Interconnect or link topology is currently audit metadata only. Cathedral
records a digest for operator review, but topology does not affect the profile
digest, component admission digest, or composite measurement until an
authenticated evidence source is specified.

## Privacy and identity reuse

Successful verification returns separate CPU and GPU audit summaries plus one
composite verdict. Public audit summaries expose counts and one-way digests, not
raw GPU UUIDs. The durable identity registry uses operator-keyed HMAC digests
for both GPU and worker identities. Verification and audit are side-effect-free.
Only after live-channel confirmation and lifecycle compare-and-swap does the
runtime finalize a two-phase identity claim. A rejected or raced admission rolls
its pending claim back; an interrupted claim fails closed for operator recovery.
Another admission for the same worker while that claim is pending is classified
as busy recovery state, not hostile cross-worker identity reuse, so it cannot
trigger identity-conflict revocation.
The transaction allows fresh reattestation by the same worker and rejects the
same physical GPU identity being claimed by a different worker. The database is
bound to its identity key and refuses to open under a different key, preventing
key rotation or misconfiguration from silently bypassing prior claims. In
production, its parent directory and database must be owner-only and may not be
symlinks. Cathedral pins their filesystem identities, reauthenticates the key
and full-state MAC after acquiring each transaction, and rejects permission,
path, schema, trigger, claim-row, or recovery-history changes. A separately
located generation file is the HMAC-authenticated monotonic high-water anchor.
It must be in a different owner-only directory and a different backup, restore,
and administrative domain from the database. Restoring or deleting the database
without the latest external generation therefore fails closed. The process
holds an inter-process lock on that anchor through the SQLite commit, so another
validator cannot authenticate a split generation. SQLite commits first. If the
process stops before the anchor advances, the next authenticated open accepts
only an exact one-generation-ahead database and completes the anchor update.
The anchor alternates between two fixed HMAC slots, so an interrupted slot write
retains the immediately previous valid generation for that reconciliation.

The local mechanism cannot detect a coordinated replay of both the database and
its external high-water anchor. Production operators must keep the anchor out of
database snapshots and restore tooling, or replace that storage boundary with a
remote or hardware-backed monotonic witness before admitting an administrator
who can replay both locations. Ordinary runtime startup never creates missing
production identity state. Creation is an explicit one-time operator ceremony:

```text
cathedral runtime initialize-gpu-identities \
  --gpu-identity-db /var/lib/cathedral/gpu-identities.sqlite \
  --gpu-identity-key-file /run/secrets/cathedral-gpu-identity.key \
  --gpu-identity-anchor-file /var/lib/cathedral-identity-anchor/generation
```

The two parent directories must already exist with owner-only permissions.
Initialization refuses an existing database or anchor, so deleting either file
cannot silently reset identity ownership during ordinary startup or recovery.
For a scored epoch, the dedicated canary's GPU identities must be absent from
the durable enrollment registry and are held under an exclusive, temporary
reservation. The runtime also compares raw in-process identity sets before it
opens the epoch, so the same GPU on a different TDX host cannot serve as both
canary and earning worker. The reservation is always released after the epoch;
an interrupted reservation fails closed for operator recovery.

Crash recovery is explicit, identity-key authenticated, and auditable:

```text
cathedral runtime recover-gpu-identities \
  --gpu-identity-db /var/lib/cathedral/gpu-identities.sqlite \
  --gpu-identity-key-file /run/secrets/cathedral-gpu-identity.key \
  --gpu-identity-anchor-file /var/lib/cathedral-identity-anchor/generation \
  --reason "validator terminated during GPU admission"
```

The command deterministically commits interrupted worker claims because the
lifecycle admission may already have succeeded. This preserves the one-GPU,
one-worker invariant even at the crash boundary. It releases temporary canary
reservations, which never create ownership. Both actions and one-way claim-token
digests are recorded in a durable recovery event before the transaction commits.
The same identity key required by normal operation must authorize recovery;
using the wrong key or running recovery with no interrupted claims fails closed.

The composite verifier establishes the attested channel-key claim, but channel
ownership is not marked passed until the validator confirms that key on the
live connection. This keeps quote verification separate from proof that the
current transport owns the quoted key.

## External collector and verifier contracts

`CATHEDRAL_GPU_COLLECT_CMD` is parsed into an absolute, credential-free argv
tuple and invoked without a shell. The collector receives canonical JSON on
standard input and returns canonical JSON containing a bounded quote,
certificate chain, and optional composite JWT. Its subprocess output has a
separate 16 MiB bound sized for base64 expansion of the maximum accepted
component; verifier verdict output retains the smaller default bound.

The collector, worker serializer, HTTPS client, and verifier all share the same
wire contract: at most two evidence components, a 1 MiB quote, eight 256 KiB
certificates, and a 32 KiB ASCII composite JWT per component. The JSON response
limit accounts for hexadecimal expansion of every binary field, and both ends
reject a component outside those limits before admission.
CPU-only clients retain a separate 128 KiB response cap. Composite clients use
one explicit 64 MiB validator-wide evidence working-set budget. Each admission
reserves the greater calculated peak of raw-response decoding or verifier
serialization, plus an 8 MiB margin for containers, pipe buffers, fixed fields,
and allocator overhead. This currently permits one maximum-size composite
response at a time even when the configured worker count is higher. The
reservation remains held while the response is decoded and expanded into the
verifier request, through composite verification and evidence disposal. This
bound also covers direct audit calls
outside an epoch so coordinated enrolled endpoints cannot multiply the large
wire cap or its in-memory expansions.

The verifier uses the same shell-free, input-, output-, and end-to-end
timeout-bounded process
runner. Each verification performs an exact preflight against the selected
signed profile and Cathedral-computed implementation digest, then requires an
exact result schema. The verifier input has a dedicated 32 MiB cap, sized for
the maximum GPU and TDX quote and certificate-chain envelopes together. A
timeout, oversized input or output, malformed JSON, duplicate
key, nonzero exit, preflight mismatch, artifact mutation, implementation
indirection, malformed nested result, or non-boolean success flag fails closed
as verifier infrastructure rather than terminal worker evidence.

Evidence-denial categories can reject the worker verdict. Verifier availability,
configuration, profile-validity, and authenticated identity-registry failures do
not become identity conflicts or immediate terminal verdicts; the standalone
probe uses the bounded lifecycle retry path, while the epoch runtime aborts the
affected operation without revoking the worker.
Verifier result-schema, authority-echo, and non-boolean protocol mismatches use
that infrastructure retry path even after preflight succeeds. Only explicit
negative evidence results become worker evidence denials. A confirmed attempt to
reuse another worker's GPU identity is different: the standalone probe and epoch
runtime both revoke it as an identity conflict.

The verifier receives a fixed credential-free environment. It must not require
secrets or credentials in its command line, inherited environment, or logs.

## Audit-only runtime path

The worker enables the two-component wire response explicitly:

```text
cathedral worker serve ... --gpu-composite
```

The worker still requires the protected-channel configuration used by TDX v2,
plus `CATHEDRAL_GPU_COLLECT_CMD`. The validator runtime enables GPU audit mode
only when all four identity/profile settings are present:

```text
cathedral runtime audit-attestation ... \
  --policy-registry policy.json \
  --policy-registry-keys trusted-keys.json \
  --policy-registry-keys-digest sha256:<trusted-key-file-digest> \
  --policy-registry-state policy-state.sqlite \
  --gpu-profile-id tdx-h100-pcie-v1 \
  --gpu-identity-db /var/lib/cathedral/gpu-identities.sqlite \
  --gpu-identity-key-file /run/secrets/cathedral-gpu-identity.key \
  --gpu-identity-anchor-file /var/lib/cathedral-identity-anchor/generation
```

`CATHEDRAL_GPU_VERIFY_CMD` supplies exactly one pinned, statically linked x86-64
ELF verifier executable and no arguments.
Every verifier sets `CATHEDRAL_GPU_VERIFY_CMD_ARTIFACTS` to a one-element JSON
array containing that same executable. The signed profile pins its digest. The
path must satisfy the root-owned immutable path checks above, and interpreted
entry points are not accepted. The
identity-key file is a 32-byte base64 value and must be owner-only in
production. The HTTPS
worker, client, and runtime carry exactly one TDX and one GPU component, verify
their shared binding, and only then promote the live channel claim. Supplying
partial GPU configuration, a CPU-only response to a GPU request, an extra
component, or GPU evidence to a CPU request is rejected without downgrade.
Both the main runtime and the standalone lifecycle probe enforce the same
production startup gate before reading enrollments: a currently active signed
registry profile, a production static external verifier, exact preflight, and
the authenticated durable GPU identity registry. They pass the profile validity
window, release, and digest into the lifecycle transaction, which checks them
again using commit-time UTC before accepting the compare-and-swap.

The standalone probe exposes the same configuration directly:

```text
cathedral-prober --production-mode --once \
  --db cathedral-enroll.sqlite \
  --policy-registry policy.json \
  --policy-registry-keys trusted-keys.json \
  --policy-registry-keys-digest sha256:<trusted-key-file-digest> \
  --policy-registry-state policy-state.sqlite \
  --gpu-profile-id tdx-h100-pcie-v1 \
  --gpu-identity-db /var/lib/cathedral/gpu-identities.sqlite \
  --gpu-identity-key-file /run/secrets/cathedral-gpu-identity.key \
  --gpu-identity-anchor-file /var/lib/cathedral-identity-anchor/generation
```

The audit command returns privacy-safe CPU/GPU component summaries, the bundle
digest, and a stable failure category. Successful output reports
`verified: true` and `admitted: false`, because no lifecycle admission occurs.
It never claims a GPU identity, dispatches SAT work, writes an epoch, or scores
the worker.

## Scoring and rollout gates

Evidence collection and an audit verdict do not make a GPU worker eligible to
earn. `CATHEDRAL_ENABLE_GPU_SCORING` defaults to `false`. Eligibility requires
that exact flag to be `true` and the verdict's complete profile authority to
appear in `CATHEDRAL_ACTIVE_GPU_PROFILE_AUTHORITIES`. The authority binds the
profile ID, exact profile digest, registry release, and registry digest. The SAT
lane requires the selected profile and matching CPU policy, rechecks the signed
validity window at qualification, and the runtime rechecks it before dispatch,
verified work resolution, and epoch completion. The ledger freezes that
complete authority into the epoch attestation and trailing-window lineage. Reusing a
profile ID in a later signed release cannot inherit earlier authorization or
work. A GPU audit row also cannot inherit work or scores from a CPU epoch.

Before either setting is enabled in production, Cathedral still requires:

1. a published first hardware profile;
2. repeated fresh evidence on a compatible confidential-GPU machine;
3. negative controls for nonce, host, device, firmware, mode, and identity
   mismatches;
4. verified destruction of any rented acceptance machine; and
5. a separate production-scoring decision.

Composite GPU receipt issuance is also fail-closed until a GPU-aware receipt
schema and profile binding land. Configuring a receipt issuer on a GPU runtime
is rejected at startup rather than aborting a scoring epoch later.

Rollback removes the profile from the active set or sets
`CATHEDRAL_ENABLE_GPU_SCORING=false`. The worker then becomes ineligible; it is
not silently reclassified as CPU or non-confidential supply.
