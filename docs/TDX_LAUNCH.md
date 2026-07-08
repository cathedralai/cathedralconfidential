# Cathedral TDX Launch Path

This is the current Phase 1 launch path. The original handoff was SNP-first,
but launch supply is already a GCP Intel TDX CVM, so Cathedral proves real CPU
attestation with TDX first and ports the same interface to SNP after launch.

## Live Box

Current launch target:

```text
name: polaris-tdx-7e93d5de
project: polaris-tdx-attest
zone: us-central1-b
machine: c3-standard-4
confidential type: TDX
role: cathedral-sn39-publisher
deletion protection: true
```

Treat it as live infrastructure. Initial probes should only request attestation
evidence and inspect read-only capability state. Do not restart services, change
config, or stop the VM as part of attestation development.

## Interface

The miner-side collector is:

```python
from cathedral.attest import collect_tdx
evidence = collect_tdx(nonce, hotkey)
```

It writes Cathedral's 64-byte `report_data(nonce, hotkey, ssh_host_key?)` value
to Linux configfs-tsm and reads the raw quote from `outblob`.

The validator-side verifier is:

```python
from cathedral.verify import verify
attested = verify(evidence, nonce, policy)
```

Python does not verify Intel quote crypto. Set `CATHEDRAL_TDX_VERIFY_CMD` to a
DCAP or Intel Trust Authority verifier that validates the quote and prints JSON
claims:

```json
{
  "report_data": "<hex or base64>",
  "measurement": "<MRTD or policy measurement>",
  "tcb": 1,
  "platform_id": "<sybil-dedup platform key>"
}
```

Cathedral then enforces:

- `REPORTDATA == report_data(nonce, hotkey, ssh_host_key?)`
- `measurement in policy.allowed_measurements`
- `tcb >= policy.min_tcb`
- `platform_id` is present and becomes the Phase 1 sybil-dedup key

For the current Polaris TDX launch box, use the adapter in
`scripts/tdx_verify_json.py` with the Polaris `attestor-verify` binary:

```bash
export CATHEDRAL_TDX_ATTESTOR_VERIFY_BIN=/tmp/attestor-verify
export CATHEDRAL_TDX_VERIFY_CMD='python scripts/tdx_verify_json.py'
```

The adapter fails closed unless `attestor-verify` returns both
`intel_verified=true` and `report_data_match=true`. It then parses policy
claims from the same verified quote bytes: a canonical Cathedral TDX
measurement over TD identity fields, `tee_tcb_svn`, REPORTDATA, MRTD, RTMRs,
TD attributes, XFAM, the TDX attestation-key fingerprint, and a
`tdx-pck-cert-sha256:*` PCK leaf certificate fingerprint used as the Phase 1
`platform_id`. Package-stable platform identity and richer DCAP TCB status
semantics remain post-launch hardening.

Keep `CATHEDRAL_TDX_MIN_TCB=0` for this adapter until DCAP TCB status is
plumbed through. The adapter exports raw `tee_tcb_svn` for auditability, but
Cathedral rejects positive TCB floors when only raw `tcb_svn` is available.
The PCK certificate fingerprint is also certificate-specific; it is a Phase 1
dedup key, not a package-stable identity guarantee.

## Hardware Test

Run quote collection + verification on the TDX CVM with the Polaris verifier
adapter:

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

Phase 1 defaults:

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

## Definition Of Done

- Hardware-free suite stays green.
- `tests/test_attest_tdx_hw.py` passes on the live TDX CVM.
- `tests/test_tdx_sat_e2e_hw.py` passes on the live TDX CVM.
- `tests/test_attest_tdx_negative.py` fails closed on a non-TDX CPU host.
- A validator epoch can admit a real TDX-attested miner and still produce
  conserved weights.
- SNP remains a second CPU platform port, not a launch blocker.

Latest live evidence, July 8, 2026:

- Hardware-free local suite: `63 passed, 3 skipped`.
- Live TDX CVM with Polaris `attestor-verify` adapter:
  parsed `tdx-measurement-sha256:24da9c7003a1199293951b8e9acbf5ae0bf94b209b6958c1c3651892df5e02ce`,
  `tdx-pck-cert-sha256:cac3ee7282e1c79c9d3bcfcad2125dce41d7ef773cf61655693b51e968baa5a2`,
  and `tee_tcb_svn=0d010800000000000000000000000000`;
  `tests/test_attest_tdx_hw.py tests/test_tdx_sat_e2e_hw.py` -> `2 passed`.
- Live verifier smoke returned an 8000-byte quote with
  `intel_verified=true`, `report_data_match=true`, 64-byte `report_data`, and
  four Intel collateral URLs.
- Non-TDX field negative control on disposable `e2-micro` Spot VM:
  `/sys/module/tdx_guest`, `/dev/tdx_guest`, and
  `/sys/kernel/config/tsm/report` were absent;
  `CATHEDRAL_RUN_TDX_NEGATIVE=1 tests/test_attest_tdx_negative.py` -> `2 passed`.
