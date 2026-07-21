# Thin subnet integration

Cathedral Confidential is a fact producer for the Cathedral thin Bittensor
validator. It does not receive the validator wallet and it does not choose or
submit weights.

The boundary is one canonical signed JSON file per completed epoch:

1. Cathedral Confidential verifies a worker and its work.
2. The ledger atomically stores the work resolution and its signed
   `cathedral_assurance_receipt_v2`.
3. `runtime export-score-class` emits `verified_work_units` plus the exact
   receipt ID, digest, and HTTPS location for each positive miner.
4. Each validator independently pins or owner-registers the report key, chooses
   the metric and class allocation, collapses same-coldkey identities, writes a
   decision record, and submits its own final vector.

This is intentionally a static-artifact integration. A source can publish the
report and receipts from inexpensive object storage, IPFS-backed storage, or
multiple HTTPS mirrors. There is no central scoring API in the validator loop,
and report size and verification work are linear in the number of scored miners.
The ledger permits one assurance receipt per miner per epoch, so provenance does
not grow with an unbounded challenge history.

The first score-class export for an epoch is frozen in the ledger. Retrying an
upload or repairing a mirror always replays the exact same bytes and report ID,
even if the command is invoked later. The exporter also links each stream to its
latest durable prior report automatically; operators do not need to copy a
`previous_report_id` between epochs.

## Export a completed epoch

The epoch must have been completed for the exact target network and netuid. The
score-class signing seed is a base64-encoded 32-byte Ed25519 seed in an
owner-only file.

```console
cathedral runtime export-score-class \
  --ledger-db ./runtime.sqlite \
  --epoch-id 7 \
  --score-network finney \
  --score-netuid 39 \
  --signing-key-id cathedral-score-2026-01 \
  --signing-key-file ./score-class.key \
  --valid-until 2026-07-21T20:05:00.000000Z \
  --valid-from-block 6200000 \
  --valid-until-block 6200100 \
  --verifier-digest sha256:<64-lowercase-hex> \
  --evidence-base-uri https://evidence.example/receipts/ \
  --output ./confidential-compute.json
```

Production export requires an evidence base URI. The validator's durable
decision record then contains the metric, source epoch, policy and verifier
digests, receipt IDs and digests, registration, class allocation, and exact UID
vector that explain the assignment.

Work-unit values outside the validator's bounded decimal grammar exclude only
that miner with the reason `unsupported_work_unit_precision`; they cannot make
the whole external class unparsable.

The validator policy remains local. A typical external class requires:

- metric `verified_work_units`;
- reason codes `receipt_verified` and `work_verified`;
- evidence kind `cathedral_assurance_receipt_v2`;
- a validator-chosen cap, transform, and allocation;
- a pinned key or a current source-subnet owner registration.

## Run the cross-repository local proof

Use a Python environment containing the thin subnet's Bittensor dependencies:

```console
PYTHONPATH="$PWD:/path/to/cathedralsubnet-production-ready" \
  /path/to/python scripts/thin_subnet_e2e.py \
  --validator-repo /path/to/cathedralsubnet-production-ready \
  --pretty
```

The command creates real signed assurance receipts in a temporary Cathedral
Confidential ledger, exports the signed score class, rejects a tampered copy,
and runs the local miner/validator/decision/retry loop. It does not broadcast to
mainnet or require hosted infrastructure.

## Remaining assumptions

- Validators trust the delegated score-report key to report facts faithfully;
  receipt references make that claim auditable but do not remove key risk.
- Validators or independent auditors must retain/fetch the referenced receipt
  bytes and verify them against the applicable policy registry.
- HTTPS/IPFS availability and historical retention are operator concerns.
- The local proof uses cryptographically real artifacts and simulated worker and
  chain responses. Mainnet registration, live TDX evidence, and an included
  `set_weights` transaction remain separate promotion gates.
