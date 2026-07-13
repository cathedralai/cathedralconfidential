# Build Status

Last verified: 2026-07-13

## Working now

- Confidential compute is the sole scoring dimension: base mass = 0,
  confidential mass = 1. The signed scorer targets testnet SN292.
- The worker serves authenticated `/info` and `/evidence` endpoints and returns
  real Intel TDX quotes.
- The confidential validator enrolls workers, issues fresh challenges, verifies
  TDX evidence and hotkey binding, runs deterministic audit work, derives the
  score, and publishes a complete score vector.
- A dedicated thin validator pinned to `confidential_primary_v1` has repeatedly
  accepted fresh signed vectors, mapped worker hotkey
  `5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK` to UID 41, and computed
  dry-run UID41 = 1.0.
- The old shared SN292 validator is disabled.
- Hardware epochs run on a 60-second cycle; each verified epoch produces 20 work
  units at score 1.0.
- Post-migration FK integrity is clean.
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
[2026-07-13T15:23:09Z] OK    5Ctob..wawK  ep=7/1  admit=Y  work=verified               wu=   20.00  score=1.000  pub=NO  ch=ababab..ababab
[2026-07-13T15:23:09Z] ZERO  5Zero..ero   ep=7/1  admit=Y  work=sat_failed             wu=    0.00  score=0.000  pub=NO  ch=cdcdcd..cdcdcd  err=invalid SAT certificate
[2026-07-13T15:23:09Z] FAIL  5Fail..ail   ep=7/1  admit=N  work=attestation_failed     wu=    0.00  score=0.000  pub=NO  err=worker returned HTTP 401
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

Chain broadcast is disabled. Wallet hotkey
`5Dk1aiJ5cXe8KJSjKMuMrwAaJhUQEKAxTHFfG8gJjpZ64f9S` is not registered on
SN292, so the validator cannot submit extrinsics.

Remaining before chain-live:

1. Register and stake the wallet hotkey on SN292, or supply a hotkey that
   already holds a permitted validator slot.
2. Explicitly enable chain broadcast in the validator config.
3. Confirm one successful weight extrinsic lands on chain.
4. Confirm that a stale or failed-evidence epoch produces zero weight
   (burn behavior).
