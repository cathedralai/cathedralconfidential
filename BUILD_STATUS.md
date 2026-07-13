# Build Status

Last verified: 2026-07-13

Current integration proof is **testnet SN292 in dry-run mode**. Production
target is SN39; SN39 chain submission is not live.

## Working now

- Confidential compute owns 100% of the score vector. There is no shared scorer,
  reserved share, or second scoring mechanism.
- The worker serves authenticated `POST /v1/evidence` and `POST /v1/sat-work`
  endpoints and returns real Intel TDX hardware quotes (8000-byte quotes with
  `intel_verified=true` and `report_data_match=true`).
- The scorer enrolls workers, issues fresh challenges, verifies TDX evidence and
  hotkey binding, runs deterministic validator-dispatched audit work, derives
  the score itself, and publishes a complete signed score vector.
- A dedicated thin validator has repeatedly accepted fresh signed vectors,
  mapped the worker hotkey to UID 41, and computed dry-run UID41 = 1.0.
- Hardware epochs run on a 60-second cycle; each verified epoch produces 20
  validator-derived work units at score 1.0.
- Post-migration foreign-key integrity is clean.
- Repository test suite: 469 passed, 3 skipped.

## Operator: pretty epoch logs

Add `--pretty` to `runtime run-epoch` for a timestamped, single-line-per-worker
summary instead of JSON. JSON remains the default.

```
# Pretty mode (human-readable)
cathedral runtime run-epoch \
  --registry-db /data/registry.sqlite \
  --ledger-db /data/ledger.sqlite \
  --measurements-file /etc/cathedral/measurements.json \
  --canary-hotkey $CANARY_HOTKEY \
  --canary-endpoint $CANARY_ENDPOINT \
  --source-epoch 7 \
  --pretty
```

Example output (one header, one line per worker, one footer):

```
[2026-07-13T15:23:01Z] EPOCH START  source=7  ep=1
[2026-07-13T15:23:09Z] OK    5Aaaa..aaaa  ep=7/1  admit=Y  work=verified               wu=   20.00  score=1.000  pub=NO  ch=ababab..ababab
[2026-07-13T15:23:09Z] ZERO  5Bbbb..bbbb  ep=7/1  admit=Y  work=sat_failed             wu=    0.00  score=0.000  pub=NO  ch=cdcdcd..cdcdcd  err=invalid SAT certificate
[2026-07-13T15:23:09Z] FAIL  5Cccc..cccc  ep=7/1  admit=N  work=attestation_failed     wu=    0.00  score=0.000  pub=NO  err=worker returned HTTP 401
[2026-07-13T15:23:09Z] EPOCH END  ep=7/1  status=complete  published=NO  workers=3  ok=1  zeros=1  fail=1
```

Indicators: `OK` = scored, `ZERO` = admitted but no verified work, `FAIL` = not
admitted. An aborted epoch appends `!! EPOCH FAILED` to the footer.

`retry-publish --pretty` emits a single acknowledgement line:

```
[2026-07-13T15:25:01Z] PUBLISH  epoch=1  ok  ack=accepted
```

JSON is always the default; omit `--pretty` in automated pipelines.

Both default JSON and `--pretty` output redact credential-shaped values
(`bearer=`, `token=`, `secret=`, `hmac=`, `api_key=`, `Authorization: Bearer ...`)
from any embedded error text before printing, and the same redaction applies
to top-level CLI exception output.

## Operator recovery: abandon-complete

A `complete` epoch is frozen and unpublished. Normally the operator publishes
it with `retry-publish`, which always resends the exact same immutable report
bytes. If the downstream ingest service permanently rejects that report (for
example, its `generated_at` has aged past the ingest service's first-publish
freshness window), `retry-publish` can never succeed for that epoch and it
will block `begin_epoch` forever.

`runtime abandon-complete` is the audited recovery: it transitions the epoch
from `complete` to a terminal `abandoned` status and unblocks `begin_epoch`.
It never mutates the frozen `report_body`/`report_digest`, requires a
nonempty `--reason`, and records that reason with a timestamp in the ledger.
Abandoned work can never become payable: `mark_published` only accepts a
`complete` epoch, and the trailing score window only reads `published`
epochs, so an abandoned epoch is excluded from both permanently. Only a
`complete` epoch can be abandoned; every other transition (running, aborted,
published, already abandoned) is rejected.

```bash
cathedral runtime abandon-complete \
  --ledger-db /data/ledger.sqlite \
  --epoch-id 42 \
  --reason "report generated_at exceeds ingest service's 24h first-publish window"
```

```json
{"abandoned_at": "2026-07-13T18:02:11.123456+00:00", "abandoned_epoch_id": 42, "reason": "report generated_at exceeds ingest service's 24h first-publish window"}
```

Older on-disk ledgers created before this status existed are migrated
automatically (in place, preserving all rows) the first time they are opened.

## Testnet boundary

**Chain broadcast is NOT live.** The validator hotkey is not registered on
SN292, so the validator cannot submit extrinsics. Everything above is dry-run:
the vector is signed, verified, and mapped, but no weights land on chain.

Remaining before chain-live:

1. Register and stake the validator hotkey on SN292, or supply a hotkey that
   already holds a permitted validator slot.
2. Explicitly enable chain broadcast in the validator config.
3. Confirm one monitored on-chain `set_weights` extrinsic lands.
4. Confirm zero-revocation acceptance: a stale or failed-evidence epoch removes
   prior weight (burn behavior).

Production (SN39) submission is a separate step. The scorer integration for
production is under review in `cathedralai/cathedral` PR #378, not merged to
production main.
