# Build Status

Last verified: 2026-07-13

## Working now

- The worker serves authenticated `/info` and `/evidence` endpoints and returns
  real Intel TDX quotes.
- The confidential validator enrolls workers, issues fresh challenges, verifies
  TDX evidence and hotkey binding, runs deterministic audit work, derives the
  score, and publishes a complete score vector.
- A live validator epoch admitted testnet SN292 UID 41, hotkey
  `5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK`, verified 20 work units,
  assigned score `1.0`, and published the resulting vector.
- The persistent confidential validator is running on a 60-second cycle. The
  repository test suite passes with 469 tests passed and 3 skipped.

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

The SN292 thin validator is running in dry mode. On-chain weight submission is
disabled while the integration is observed. The successful live epoch reached
the worker over the private Polaris network; the worker's public port was not
reachable from the SN292 validator at the last check.

Before enabling testnet weights, the SN292 validator must receive the complete
confidential score stream, map the enrolled hotkey to UID 41, pass a dry-run
vector check, and prove both a successful weight extrinsic and zero weight after
a failed or stale worker epoch.
