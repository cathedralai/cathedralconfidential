# Confidential-GPU Worker contract

Status: blocking launch track, `NOT PROVEN` on live hardware. This document
defines the selected software contract. It does not advertise customer
availability.

## Selected first profile

`gcp-a3-high-h100-tdx-v1` is deliberately fixed to:

- Google Cloud `a3-highgpu-1g` in `us-central1-a`;
- one NVIDIA H100 80 GB GPU and Intel TDX;
- a Google Confidential Space production `STABLE` image;
- one digest-pinned Cathedral workload container;
- Google Cloud Attestation PKI composite evidence; and
- Spot provisioning only, with maximum-run termination and `DELETE` as the
  termination action.

The fixed profile does not use Flex-start, MIG, on-demand capacity, an Ubuntu
Confidential VM assembled by Cathedral, or a local NVAT/Trustee verifier. A
replacement attempt always uses a newly created instance. It never restarts a
failed or suspect instance in place.

Primary platform evidence:

- [Confidential Space workload deployment](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads)
- [Confidential Space token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [Confidential Space images](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-images)
- [Confidential VM supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)
- [Confidential VM with GPU](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance-with-gpu)
- [NVIDIA attestation troubleshooting](https://docs.nvidia.com/attestation/advanced-documentation/latest/attestation-troubleshooting-guide/attestation_troubleshooting_guide_common.html)

The verifier requires a Google-signed token for one Intel TDX guest and exactly
one `GCP_NVIDIA_H100` entry with `cc_feature=SPT`, `cc_mode=ON`, an allowlisted
driver and VBIOS, and stable pseudonymous device identity fields. Google notes
that the `cc_mode` claim attests the GPU driver claim; Cathedral therefore also
requires a channel-owned, same-container local H100 identity and ReadyState
assertion. That assertion becomes launch evidence only when the digest-pinned
container and real A3/H100 round trip are observed.

## Product classes

| Execution class | CPU evidence | GPU evidence | GPU memory claim | Confidential-GPU policy |
|---|---|---|---|---|
| `tdx_cpu` | Intel TDX | None | Not applicable | Separate existing class |
| `hybrid_gpu_preview` | TDX controller | Provider provenance | Provider trusted | Never accepted |
| `cc_gpu` | Intel TDX | Google-signed NVIDIA CC claims plus bound local ReadyState | Accepted only under the pinned profile | Eligible only after the live gate |

Capacity, preemption, cancellation, or verification failure never downgrades a
`cc_gpu` request to another class.

## Fixed proof workload

The first profile is not arbitrary inference. It executes only:

```text
/usr/bin/python3 /opt/cathedral/bin/cathedral-job
```

The measured first-party CUDA program multiplies two equal-length, finite,
little-endian float32 vectors on one H100. It has no CPU fallback. The request
must contain exactly two protected inputs in this order:

1. `kind=input`, mounted as `/work/input.bin`;
2. `kind=model`, mounted as `/work/model.bin`.

Each plaintext is at most 256 MiB. The only declared output is
`result.json`, at most 262,144 bytes, using schema
`cathedral_cc_gpu_cuda_vector_result_v1`. Checkpointing is `none`; retry is
`restart_from_zero`.

## Owner-bound protected-input staging

Polaris derives an opaque owner digest from the authenticated account with a
dedicated secret. The digest, not its preimage, is returned by the authenticated
staging-binding endpoint. It is distinct from the worker UUID and
`subject_hotkey`.

The customer stager then:

1. encrypts the input locally as bounded 4 MiB AES-256-GCM chunks;
2. includes `owner_digest` in the canonical sealed record;
3. asks authenticated Polaris to sign a five-minute staging authorization;
4. sends the sealed record and authorization to
   `POST /v1/staging/sealed-inputs` over server-authenticated TLS; and
5. after receiving a KBS-signed acknowledgment containing no data key or
   nonce, uploads ciphertext with `ifGenerationMatch=0` to the
   content-addressed `gs://.../sealed-inputs/sha256/<ciphertext>.ccgpu` object
   and reads it back to verify the exact digest and size.

The Polaris authorization binds its UUID, owner digest, canonical sealed-record
digest, kind, object reference, ciphertext and plaintext digests and sizes,
validity window, and authority key. KBS pins a separate staging-authority key,
requires exact equality with the sealed record, and durably consumes the
authorization. An exact retry after a lost response is idempotent; reuse of the
same authorization ID for any different signed artifact fails closed.
Ciphertext is not published before both owner authorization and KBS
registration succeed, so either failure leaves no unowned GCS object.

`POST /v1/admin/sealed-inputs` remains an operator acceptance/recovery path
protected by the dedicated KBS admin mTLS CA. It is not a customer-staging
credential or API.

Customer job-request declarations omit `owner_digest`; Polaris derives and
injects it into the accepted server-side contract, where it accompanies only
content references, digests, and byte counts. Polaris never receives a
plaintext, data key, nonce, or output private key.

The supported customer path is the `stage-input` binary from this repository.
After the live profile is available, the operator supplies a signed onboarding
bundle containing the exact binary digest, Polaris staging-authority public
key, KBS TLS CA, KBS signing public key, immutable GCS bucket/prefix policy, and
their key IDs. These are public trust anchors; the bundle contains no KBS admin
certificate and no private signing key. Store the Cathedral bearer token in a
non-symlink file with mode `0600`, then stage the two equal-length raw float32
vectors independently:

```bash
stage-input \
  --input "$PWD/input.bin" --kind input \
  --bucket "$CATHEDRAL_CC_GPU_STAGING_BUCKET" \
  --prefix "$CATHEDRAL_CC_GPU_STAGING_PREFIX" \
  --temp-dir "$CATHEDRAL_CC_GPU_TEMP_DIR" \
  --gcloud "$CATHEDRAL_GCLOUD_PATH" \
  --polaris-origin https://cathedral.computer \
  --polaris-api-token-file "$CATHEDRAL_API_TOKEN_FILE" \
  --staging-authority-key-id "$CATHEDRAL_STAGING_KEY_ID" \
  --staging-authority-public-key-base64 "$CATHEDRAL_STAGING_PUBLIC_KEY_BASE64" \
  --kbs-origin "$CATHEDRAL_KBS_ORIGIN" \
  --kbs-server-name "$CATHEDRAL_KBS_SERVER_NAME" \
  --kbs-root-ca "$CATHEDRAL_KBS_ROOT_CA" \
  --kbs-signing-key-id "$CATHEDRAL_KBS_SIGNING_KEY_ID" \
  --kbs-signing-public-key-base64 "$CATHEDRAL_KBS_SIGNING_PUBLIC_KEY_BASE64" \
  > input.declaration.json

stage-input \
  --input "$PWD/model.bin" --kind model \
  --bucket "$CATHEDRAL_CC_GPU_STAGING_BUCKET" \
  --prefix "$CATHEDRAL_CC_GPU_STAGING_PREFIX" \
  --temp-dir "$CATHEDRAL_CC_GPU_TEMP_DIR" \
  --gcloud "$CATHEDRAL_GCLOUD_PATH" \
  --polaris-origin https://cathedral.computer \
  --polaris-api-token-file "$CATHEDRAL_API_TOKEN_FILE" \
  --staging-authority-key-id "$CATHEDRAL_STAGING_KEY_ID" \
  --staging-authority-public-key-base64 "$CATHEDRAL_STAGING_PUBLIC_KEY_BASE64" \
  --kbs-origin "$CATHEDRAL_KBS_ORIGIN" \
  --kbs-server-name "$CATHEDRAL_KBS_SERVER_NAME" \
  --kbs-root-ca "$CATHEDRAL_KBS_ROOT_CA" \
  --kbs-signing-key-id "$CATHEDRAL_KBS_SIGNING_KEY_ID" \
  --kbs-signing-public-key-base64 "$CATHEDRAL_KBS_SIGNING_PUBLIC_KEY_BASE64" \
  > model.declaration.json
```

Each stdout document is the exact owner-free object accepted in the job's
`protected_inputs` array. The stager itself calls authenticated
`GET /v1/workers/cc-gpu/staging-binding` and
`POST /v1/workers/cc-gpu/staging-authorization`; customers do not copy the
opaque owner digest into the job request.

## Attempt and KBS binding

Each retry has a new `attempt_id`, provider numeric instance ID, random
challenge, Ed25519 channel key, token nonce set, TLS exporter binding, KBS
release request, and completion challenge. The exact job-context construction
is domain-separated and length-framed by the API contract. It commits to the
worker, subject hotkey, owner-bound protected inputs, attempt, profile,
provider, image, policy, and provisioning fields.

Vendor documentation records attestation-mismatch cases whose operational
recovery is a full stop/start. Cathedral treats such a mismatch as a failed
attempt: it fails closed, deletes that provider resource, and may create a
fresh attempt within policy. It never restarts the same attempt or reuses its
evidence, channel, nonce, or release state.

The instance starts locked and receives no runnable signed configuration.
Polaris first observes its numeric instance ID, registers the exact expected
contract over the dedicated KBS admin mTLS endpoint, verifies the KBS-signed
registration acknowledgment, and only then publishes the signed supervisor
configuration containing that acknowledgment digest. Failure in registration
or publication cancels and deletes the instance.

The guest obtains fresh Google Attestation PKI evidence on the same TLS 1.3
session used for KBS release. The token nonce set commits to the immutable
challenge, channel-owned ReadyState, and TLS exporter material. KBS independently
re-verifies the token and exporter binding, checks the signed release policy,
and durably journals one release response for the attempt. An exact retry on
the same EKM-bound TLS session returns those byte-identical committed keys; a
changed request or replacement TLS connection fails closed. Release returns
the two input keys and one KBS-generated output key only to the attested guest
session. Completion uses the same rule: its exact challenge start is
idempotent before consumption, and its verified acknowledgment is durably
journaled before return so a lost response can be retried byte-for-byte on the
same EKM-bound connection. A changed completion submission remains consumed
and fails closed.

## Runtime and lifecycle

The fixed first-party workload runs as UID 65532 with no supplementary groups,
no Linux capabilities, `no_new_privs`, a read-only recursive root mount, fixed
`/work`, masked read-only `/run`, `/tmp`, `/var/tmp`, `/dev/shm`, and
`/dev/mqueue`, bounded tmpfs/cgroups, and separate network, mount, PID, IPC, and
UTS namespaces. The `unshare` parent is placed in its cgroup atomically during
`clone3`, before it can run or fork, so no descendant can escape the configured
memory, PID, or CPU bounds. The workload child has no routes, metadata access,
control-plane credentials, or network sockets. The supervisor alone may reach
the exact control-store and KBS endpoints.

These controls are a contract for the fixed measured proof workload. They are
not a claim that the first profile safely runs arbitrary customer code.

Cancellation fences the attempt and deletes the provider resource.
Preemption/capacity retry creates a fresh attempt only within the signed retry,
runtime, and spend bounds. Evidence, owner, channel, policy, key release,
isolation, result, or cleanup mismatch is terminal for that attempt. Completion,
cancellation, and terminal failure are not final until a signed observation
confirms the provider instance is absent.

## Output, receipt, and validator policy

The guest seals `result.json` under the KBS-generated output key, then wraps
that key to the request's X25519 recipient. A fresh completion token must bind
the same attempt channel, result digest, artifact-manifest digest, KBS release
acknowledgment, and the same GPU identity set as admission.

The `cathedral_cc_gpu_job_receipt_v1` records `execution_class=cc_gpu`, the
profile, owner-independent public job identity, admission/completion evidence
digests, channel, release-policy/ack bindings, result and artifact digests, and
confirmed deletion. Validators independently replay the evidence and accept
only unique, completed, policy-current jobs. Hybrid-preview receipts never
satisfy this policy.

## Non-launch experimental code

The Python Trustee/raw-NVAT adapter retained under `cathedral/trustee.py` is an
experimental compatibility path. It is not the selected GCP launch verifier,
must not set availability, refuses CC-GPU grants in production mode, and cannot
substitute for the external Go KBS, a Confidential Space composite PKI token,
or live proof.

## Terminal gate

Software-only tests may establish the code contract. Launch remains
`NOT PROVEN` until one real supported Spot A3/H100 attempt produces, in one
observed chain: fresh composite admission; KBS release; confidential CUDA job;
customer output decryption and recomputation; fresh bound completion; signed
receipt; confirmed deletion; and validator ingestion with replay and negative
controls. No local simulation can satisfy this gate.
