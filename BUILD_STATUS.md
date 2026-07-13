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
  repository test suite passes with 341 tests passed and 3 skipped.

## Testnet boundary

The SN292 thin validator is running in dry mode. On-chain weight submission is
disabled while the integration is observed. The successful live epoch reached
the worker over the private Polaris network; the worker's public port was not
reachable from the SN292 validator at the last check.

Before enabling testnet weights, the SN292 validator must receive the complete
confidential score stream, map the enrolled hotkey to UID 41, pass a dry-run
vector check, and prove both a successful weight extrinsic and zero weight after
a failed or stale worker epoch.
