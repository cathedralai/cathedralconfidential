# Confidential-GPU launch scorecard

Only `PASS`, `FAIL`, and `NOT PROVEN` are valid verdicts. A software fixture
cannot satisfy a live or deployed gate.

| Gate | Required terminal evidence | Verdict |
|---|---|---|
| Concrete target selection | Primary Google evidence supports Confidential Space on one TDX-backed A3 High H100 in the selected zone and provisioning model | PASS |
| Local development hardware | Local host exposes supported TDX, H100, driver, and attestation stack | FAIL |
| Owner-bound staging contract | Authenticated owner binding, customer-local encryption, short-lived signed staging authorization, KBS owner/record equality, exact retry, and substitution/replay rejection all pass | PASS |
| Composite verifier software | Full Go race tests accept valid synthetic Google PKI claims and reject stale, duplicate, mismatched, multi-GPU, CC-off, debug, mutable-image, and channel-substitution cases | PASS |
| KBS release software | Dedicated admin mTLS, exact keyless registration, signed positive-lifetime policy, TLS-exporter evidence verification, byte-identical release and completion response journaling for exact same-session retry, changed-request rejection, and completion replay fencing pass | PASS |
| Fixed runtime code | Fixed H100-only CUDA vector job, no CPU fallback, namespace/mount isolation, atomic pre-fork cgroup placement, protected-input decrypt, output sealing, cancellation, and cleanup tests pass | PASS |
| Native amd64 runtime build | The pinned multi-stage Dockerfile builds and passes the no-H100 fail-closed smoke test on a native amd64 CI runner | PASS |
| Production runtime image | The exact CI-reviewed image is published to the protected registry and the launch policy pins its immutable manifest digest | NOT PROVEN |
| Cross-repository software lifecycle | Polaris focused API/lifecycle tests exercise create, get, cancel, retry, output, evidence, receipt, billing, and failure states against PostgreSQL; the separately tested production command adapter has no simulated fallback | PASS |
| Validator policy | Synthetic cross-repo export is accepted once and stale, duplicate, hybrid, substituted, or policy-mismatched evidence is rejected | PASS |
| GCP quota/capacity | Read-only quota supports one H100 and a bounded Spot `a3-highgpu-1g` allocation succeeds in `us-central1-a` | NOT PROVEN |
| Live confidential job | Fresh composite admission, KBS release, H100-only CUDA result, customer decrypt/recompute, fresh completion, signed receipt, and confirmed deletion are one bound chain | NOT PROVEN |
| Live validator ingestion | The real receipt is independently replayed and accepted exactly once; negative controls receive no reward | NOT PROVEN |
| Public availability | Signed current launch proof and operational readiness enable the capability without changing hybrid-preview labels | NOT PROVEN |

The exact approval boundary is the first paid/quota-changing action needed to
obtain the live Spot A3/H100 chain. Until every preceding software gate is
`PASS`, no quota request or allocation should be proposed. Even after software
completion, no paid capacity, quota request, production mutation, deployment,
merge, or mainnet action occurs without explicit approval.
