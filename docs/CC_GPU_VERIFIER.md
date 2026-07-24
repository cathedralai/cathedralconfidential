# Confidential-GPU production verifier

Status: software implementation present; live launch evidence `NOT PROVEN`.

## Selected evidence path

`cmd/cathedral-confidential-space/cmd/verifier` is the selected verifier for
`gcp-a3-high-h100-tdx-v1`. It verifies Google Cloud Attestation PKI composite
tokens produced by a digest-pinned Cathedral container on a Confidential Space
Spot `a3-highgpu-1g` instance in `us-central1-a`.

The selected launch path does not ask a stock Confidential Space guest for a
raw TDX quote or raw NVIDIA NVAT blob. It does not trust a provider boolean and
has no fake-success mode. The older Python Trustee/raw-NVAT adapter is
experimental and non-launch.

Primary claim references:

- [Attestation token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [Connect to external resources](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)
- [Grant access to confidential resources](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources)

## Exact verification

For admission and completion, the verifier fails closed unless all of these
hold:

1. The compact JWT is RS256, contains the documented three-certificate chain,
   and terminates at the digest-pinned Google Attestation PKI root.
2. Issuer, audience, validity, service account, project, zone, numeric instance
   ID, instance-name prefix, production Confidential Space software version,
   secure boot, non-debug state, source image, and container image/args/env are
   exactly policy allowed.
3. CPU claims identify Intel TDX, with an allowlisted TCB status and date.
4. NVIDIA claims contain exactly one `GCP_NVIDIA_H100`, `cc_feature=SPT`,
   `cc_mode=ON`, and allowlisted driver/VBIOS, with canonical UEID, serial, and
   identity fields.
5. The token nonce set exactly matches domain-separated values derived from the
   immutable challenge, local ReadyState, and the KBS TLS exporter digest.
6. A fresh Ed25519 channel key signs the exact channel proof and local H100
   ReadyState assertion. The assertion binds phase, job context, nonce, GPU
   count/model/pseudonymous UUID, and the same channel/TLS session.
7. Completion uses a different fresh nonce, the admission channel, the same GPU
   identity set, and exact result, manifest, KBS release-ack, and finalize
   bindings.

The verifier emits canonical replay artifacts for the composite bundle, TDX
claims, NVIDIA claims, and GPU identity set. Polaris remains the durable global
replay authority and atomically claims nonce/evidence digests across attempts.

## Evidence limits

Google's `cc_mode` token claim describes the GPU driver's confidential mode;
it is not, alone, proof of the complete device/runtime/job chain. Cathedral's
same-guest ReadyState conclusion is therefore conditional on all of:

- the Google-signed one-GPU claim;
- the digest-pinned Confidential Space image and Cathedral container;
- the measured collector path that obtains local H100 identity/ReadyState;
- channel ownership and TLS exporter binding; and
- the real completion/result round trip.

Synthetic PKI fixtures prove parser and binding behavior only. They do not
prove that the selected image exposes the expected NVIDIA device/driver to the
container, that ReadyState is genuine on the target, or that GPU memory and the
job were confidential in a live allocation.

## Policy and release artifacts

Production builds embed the absolute verifier policy path and its SHA-256
digest. The canonical policy pins the Google root, profile authority, project,
zone, source image, service account, allowed Confidential Space versions, TDX
policy, NVIDIA driver/VBIOS, exact container, trusted KBS/deletion/receipt keys,
KBS configuration digest, and freshness bounds.

KBS independently runs the same pinned static verifier for release and
completion. Its signed release policy binds owner digest, job/attempt/context,
ordered sealed-record digests, protected-input-set digest, output recipient,
and a strictly positive validity window. Release control and receipt replay
must carry the exact signed policy and acknowledgment digests.

The KBS configuration also pins a separate Polaris staging-authority key set.
Customer input staging uses a short-lived owner/record-bound authorization at
`/v1/staging/sealed-inputs`; the KBS admin mTLS CA remains reserved for job
registration and operator acceptance/recovery.

## Launch boundary

The verifier, KBS, supervisor, and replay tests can move software gates to
`PASS`. The product gate remains `NOT PROVEN` until real A3/H100 evidence shows
admission, key release, fixed CUDA execution, customer output round trip,
completion, receipt, deletion, and validator ingestion for the same unique
attempt. Availability must remain disabled until that complete artifact set is
signed, current, and independently reverified.
