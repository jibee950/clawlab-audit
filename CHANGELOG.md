# Changelog

All notable changes to ClawLab Audit are documented here.

## [0.3.0] - 2026-11-20

### Improved
- Sign journal checkpoints and recovery backups with a local Ed25519 key stored separately from journal files; reject rewritten checkpoints that do not have a valid signature.
- Migrate valid legacy unsigned checkpoints to the signed format.
- Refuse to recreate a missing checkpoint when a non-legacy backup shows that checkpointed storage was already in use.
- Preserve recovery from a process crash after journal replacement and before checkpoint replacement by detecting the mismatch and restoring the previous backup.
- Retry Windows byte-lock acquisition beyond the C runtime's ten-attempt `LK_LOCK` limit, so contending writers wait instead of failing spuriously.
- Extend concurrent-write assertions to check that every producer's operation is present exactly once.

### Tests
- Verify signatures, reject recomputed checkpoint tampering and corrupted backup signatures, and cover migration of a legacy checkpoint.
- Add an orphan-event case with a fully recomputed local hash chain and verify that the unchanged checkpoint rejects it.
- Add a real subprocess crash between journal and checkpoint replacement, then verify recovery preserves the previously committed operation and the interrupted journal copy.
- Add a missing-checkpoint regression test after a versioned backup exists.
- Keep the explicit limits visible: a fully recomputed journal remains internally valid when the actor can also rewrite its local reference data.

## [0.2.0] - 2026-11-19

### Added
- Operation search and detailed inspection.
- Filtering by agent, model, tool, result and date.
- JSON and CSV exports.
- HTML report generation.
- Execution statistics.
- Basic anomaly detection.
- Repeated tool failure alerts.
- Visual critical alerts in HTML reports.
- Local journal backup and recovery.
- Expanded automated test coverage.

### Improved
- Journal schema compatibility with older entries.
- Journal validation and corruption handling.
- Safer journal writing with temporary files and atomic replacement.
- Documentation and usage examples.

## [0.1.0]

### Added
- Initial Python execution auditing.
- Synchronous and asynchronous function support.
- UTC timestamps and execution duration.
- Local JSON journal.
- SHA-256 hash-chain integrity verification.
