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
  "platform_id": "<stable physical platform id>"
}
```

Cathedral then enforces:

- `REPORTDATA == report_data(nonce, hotkey, ssh_host_key?)`
- `measurement in policy.allowed_measurements`
- `tcb >= policy.min_tcb`
- `platform_id` is present and becomes the sybil-dedup key

## Hardware Test

Run quote collection + verification on the TDX CVM once the verifier command is
installed:

```bash
CATHEDRAL_RUN_TDX_HW=1 \
CATHEDRAL_TDX_VERIFY_CMD='tdx-verifier-json' \
CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<measurement>' \
python -m pytest tests/test_attest_tdx_hw.py -q
```

Run the full launch lane path on the TDX CVM:

```bash
sudo env \
  CATHEDRAL_RUN_TDX_HW=1 \
  CATHEDRAL_TDX_VERIFY_CMD='tdx-verifier-json' \
  CATHEDRAL_TDX_ALLOWED_MEASUREMENT='<measurement>' \
  python -m pytest tests/test_tdx_sat_e2e_hw.py -q
```

Optional:

```bash
export CATHEDRAL_TDX_MIN_TCB=0
export CATHEDRAL_TDX_TSM_REPORT_ROOT=/sys/kernel/config/tsm/report
```

## Definition Of Done

- Hardware-free suite stays green.
- `tests/test_attest_tdx_hw.py` passes on the live TDX CVM.
- `tests/test_tdx_sat_e2e_hw.py` passes on the live TDX CVM.
- A validator epoch can admit a real TDX-attested miner and still produce
  conserved weights.
- SNP remains a second CPU platform port, not a launch blocker.
