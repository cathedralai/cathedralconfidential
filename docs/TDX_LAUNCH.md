# Cathedral TDX Launch Path

This is the current Phase 1 launch path. The original handoff was SNP-first,
but launch supply is already an Intel TDX confidential VM, so Cathedral proves
real CPU attestation with TDX first and ports the same interface to SNP after
launch.

## Live Box

The current launch worker is a cloud Intel TDX confidential VM (a 4-vCPU
TDX-capable instance running the Cathedral publisher). Deployment identifiers
(VM name, project, zone, addresses) are intentionally kept out of this public
doc.

Treat it as live infrastructure. Initial probes should only request attestation
evidence and inspect read-only capability state. Do not restart services, change
config, or stop the VM as part of attestation development.

## Verifier Subprocess Controls

The validator-side subprocess verifier is governed by three environment variables:

| Variable | Default | Description |
|---|---|---|
| `CATHEDRAL_TDX_VERIFY_CMD` | *(required)* | Command (plus any fixed args) that receives the quote file path as a final argument and must print a JSON claims object to stdout. |
| `CATHEDRAL_TDX_VERIFY_TIMEOUT` | `30` | Seconds before the subprocess is killed. Timeout causes the miner to be rejected without hanging the epoch. |
| `CATHEDRAL_TDX_VERIFY_MAX_OUTPUT` | `1048576` (1 MiB) | Maximum bytes of stdout (or stderr) accepted. Output exceeding this limit is rejected without parsing. |

All modes require both `intel_verified` and `report_data_match` to be the exact
JSON boolean `true`. Missing fields, JSON strings (`"true"`), integers (`1`),
`null`, or `false` all reject.

The subprocess itself is rejected (returns no claims) if:
- it exceeds `CATHEDRAL_TDX_VERIFY_TIMEOUT` seconds
- it exits with a nonzero code
- its stdout or stderr exceeds `CATHEDRAL_TDX_VERIFY_MAX_OUTPUT` bytes
- its stdout is not valid JSON
- its stdout is valid JSON but not an object

## Interface

The miner-side collector is:

```python
from cathedral.attest import collect_tdx
evidence = collect_tdx(
    nonce,
    hotkey,
    channel_binding=worker_channel_binding,
    report_data_version=2,
)
```

It writes Cathedral's 64-byte `report_data_v2(nonce, hotkey, channel_binding)`
value to Linux configfs-tsm and reads the raw quote from `outblob`. The worker
must be configured with the digest of a channel key generated and held inside
the attested environment. It must not attest an arbitrary digest supplied by a
requesting client.

The validator-side verifier is:

```python
from cathedral.verify import verify
attested = verify(evidence, nonce, policy)
```

Python does not verify Intel quote crypto. Set `CATHEDRAL_TDX_VERIFY_CMD` to a
DCAP or Intel Trust Authority verifier that validates the quote and prints JSON
claims. The strict contract is:

```json
{
  "report_data": "<hex or base64>",
  "measurement": "<MRTD or policy measurement>",
  "tcb_svn": "<32 lowercase hex characters>",
  "tcb_status": "UpToDate",
  "advisory_ids": [],
  "debug_enabled": false,
  "collateral_current": true,
  "stable_platform_id": "tdx-platform-sha256:<64 lowercase hex characters>",
  "platform_id": "tdx-platform-sha256:<same 64 lowercase hex characters>",
  "platform_identity_kind": "stable",
  "platform_identity_verified": true,
  "claims_bound_to_quote": true,
  "tdx_pck_cert_id": "tdx-pck-cert-sha256:<64 lowercase hex characters>",
  "tdx_attestation_key_id": "tdx-ak-sha256:<64 lowercase hex characters>",
  "intel_verified": true,
  "report_data_match": true
}
```

In strict mode Cathedral enforces:

- `REPORTDATA == report_data_v2(nonce, hotkey, channel_binding)` in production
- `measurement in policy.allowed_measurements`
- a recognized, explicitly allowed DCAP TCB status
- an exact advisory allowlist; every non-`UpToDate` exception must name at
  least one advisory
- `Revoked` is never configurable as an allowed state
- debug is disabled and collateral is current
- the status and package-stable identity claims are bound to the same verified
  quote evaluation
- the stable identity is canonical and differs from the rotating PCK and
  attestation-key audit fingerprints

Raw `tee_tcb_svn` remains in the audit verdict but is not numerically ordered
for strict admission. Unknown future status strings and absent, malformed, or
contradictory typed claims fail closed.

## Production channel binding

Production endpoints use HTTPS. The evidence request is credential-free and
names the TLS SPKI digest observed by the validator. The worker accepts that
request only when the digest equals its configured in-guest key, then binds it
into the fresh quote. After quote verification, the validator reopens the TLS
connection, checks the same SPKI before writing any request bytes, and only then
sends work and its bearer credential.

Configure the loopback worker behind the in-guest TLS endpoint with the public
digest (the digest is not a secret):

```bash
cathedral worker serve \
  --hotkey "$MINER_HOTKEY" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256"
```

The TLS private key must terminate inside the measured environment. A public
certificate by itself does not prove confidential execution. Plain HTTP is
limited to the explicit development loopback flag and cannot satisfy the
production channel claim.

A production policy file looks like:

```json
{
  "allowed_measurements": ["tdx-measurement-sha256:<approved digest>"],
  "tdx_strict": true,
  "tdx_allowed_tcb_statuses": ["UpToDate"],
  "tdx_allowed_advisories": []
}
```

Add a non-current status and its advisory only as a narrow, reviewed exception.
For example, allowing `SWHardeningNeeded` does not admit an unlisted advisory.
`Revoked` and unknown statuses cannot be configured.

Use the adapter in `scripts/tdx_verify_json.py` with an `attestor-verify`
DCAP binary:

```bash
export CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify
export CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py'
```

The adapter fails closed unless `attestor-verify` returns both
`intel_verified=true` and `report_data_match=true`. It parses the debug bit,
measurement, raw SVN, PCK fingerprint, and attestation-key fingerprint from the
same verified quote bytes. If the external verifier also returns a bounded
package-stable identity with `platform_identity_verified=true` and
`claims_bound_to_quote=true`, the adapter domain-separates and hashes that value
before emitting it; raw platform identifiers are never printed.

Compatibility mode exists only for controlled migration. It preserves the
legacy scalar-TCB and certificate-specific identity behavior and marks every
successful verdict with `policy_mode="compatibility"`; the verifier also emits
a warning. Strict verdicts carry `policy_mode="strict"`. Production receipts
must retain this mode so downstream auditors can distinguish the two. Do not
describe compatibility-mode evidence as package-stable or current under the
strict TDX policy. Compatibility mode also rejects empty, control-containing,
or excessively long identity strings; this fail-closed input bound is stricter
than the original launch adapter.

## Hardware Test

Run quote collection + verification on the TDX CVM with the verifier adapter:

```bash
sudo env \
  PYTHONPATH="$PWD" \
  CATHEDRAL_RUN_TDX_HW=1 \
  CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py' \
  CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify \
  CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<tdx-measurement-sha256:...>' \
  python -m pytest tests/test_attest_tdx_hw.py -q
```

Run the full launch lane path on the TDX CVM:

```bash
sudo env \
  PYTHONPATH="$PWD" \
  CATHEDRAL_RUN_TDX_HW=1 \
  CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py' \
  CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify \
  CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<tdx-measurement-sha256:...>' \
  python -m pytest tests/test_tdx_sat_e2e_hw.py -q
```

Compatibility-only defaults:

```bash
export CATHEDRAL_TDX_MIN_TCB=0
export CATHEDRAL_TDX_TSM_REPORT_ROOT=/sys/kernel/config/tsm/report
```

Run the negative control on a plain Linux CPU host. This should fail before
quote collection because the host does not expose the TDX configfs-tsm report
root:

```bash
CATHEDRAL_RUN_TDX_NEGATIVE=1 \
python -m pytest tests/test_attest_tdx_negative.py -q
```

## Dedicated Compute Stream Launch Gate

After the hardware gates, test the compute publisher and the thin validator
together. Production chain submission is live on mainnet SN39; testnet SN292
remains the non-paying dry-run integration lane. The gate below is written
against the production metagraph and applies identically to SN292 except that
testnet chain submission stays disabled.
Launch acceptance requires all of the following:

1. A real TDX miner enrolls with its registered hotkey and passes fresh-nonce,
   measurement, TCB, and platform policy.
2. Cathedral dispatches useful work plus an unpredictable audit task,
   independently verifies both, and derives all credit itself.
3. The publisher freezes and signs a complete epoch stream. Missing, failed,
   stale, and revoked miners are present with explicit zero scores.
4. Every signed hotkey maps to exactly one current metagraph UID. Missing and
   duplicate mappings fail closed before submission.
5. The thin validator consumes the compute vector as its sole score input,
   conserves it through Bittensor u16 quantization, and submits it on chain.
6. A subsequent zero report removes the miner's prior weight, and all
   validators consuming the same signed epoch submit the same mapped vector.

`scripts/cross_repo_launch_verify.py` still encodes the retired mixed-vector
contract and is not launch evidence for this mechanism. Production acceptance
uses the sole-input `confidential_primary_v1` policy merged in
`cathedralai/cathedral` PR #378 plus the monitored SN39 chain submission.

## Definition Of Done

- Hardware-free suite stays green.
- Strict policy rejects every missing or malformed typed claim and every
  unapproved status/advisory combination.
- Repeated quotes across PCK rotation retain one package-stable identity while
  preserving the rotating PCK and attestation-key fingerprints for audit.
- `tests/test_attest_tdx_hw.py` passes on the live TDX CVM.
- `tests/test_tdx_sat_e2e_hw.py` passes on the live TDX CVM.
- `tests/test_attest_tdx_negative.py` fails closed on a non-TDX CPU host.
- A validator epoch can admit a real TDX-attested miner and still produce
  conserved weights.
- The publisher signs a complete Cathedral compute stream and the existing
  validator consumes it as its sole score input.
- Two validators map the same signed stream identically, including zero
  revocation after a miner disappears or fails work.
- SNP remains a second CPU platform port, not a launch blocker.

Compatibility-mode live evidence recorded July 8, 2026:

- Hardware-free local suite passed; hardware-gated cases were skipped in that
  environment.
- Live TDX CVM with the `attestor-verify` adapter:
  parsed `tdx-measurement-sha256:24da9c7003a1199293951b8e9acbf5ae0bf94b209b6958c1c3651892df5e02ce`,
  `tdx-pck-cert-sha256:cac3ee7282e1c79c9d3bcfcad2125dce41d7ef773cf61655693b51e968baa5a2`,
  and `tee_tcb_svn=0d010800000000000000000000000000`;
  both the TDX quote round trip and SAT lane end-to-end hardware tests passed.
- Live verifier smoke returned an 8000-byte quote with
  `intel_verified=true`, `report_data_match=true`, 64-byte `report_data`, and
  four Intel collateral URLs.
- Non-TDX field negative control on a disposable non-TDX Linux host:
  `/sys/module/tdx_guest`, `/dev/tdx_guest`, and
  `/sys/kernel/config/tsm/report` were absent;
  the enabled non-TDX negative-control test module passed.

This historical run predates the strict typed-claim contract. It remains valid
evidence for quote collection, signature verification, nonce binding, and the
SAT lane, but it is not evidence that strict platform-identity or TCB-status
policy passed. A fresh strict-mode canary is required before making that claim.
