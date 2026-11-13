# Submission: Interaction Ledger & Reporting Pipeline

## Implementation overview

The solution is a Python CLI backed by SQLite. Workflow field definitions are loaded from `schemas/<workflow_id>.json`; disposition terminal/success flags are loaded from `schemas/dispositions.csv`. The generator is included under `tools/` for local reproducibility.

### Database model

- `leads`: one row per `(workflow_id, phone_hash)`. Stores encrypted canonical phone and encrypted customer name, the original first-seen `batch_id`, the external reference, and JSON for non-PII schema fields.
- `ledger`: append-only event facts keyed by globally unique `event_id`. Event content and payload are retained; the raw JSON copy deliberately omits the phone. `lead_id` is nullable link metadata and can be populated later when a lead arrives.
- `seen_event_ids`: deduplication keys for all syntactically valid events, including unknown-disposition events that are excluded from report calculations.
- `orphan_events`: derived quarantine index rebuilt from currently unlinked ledger rows. This allows an earlier orphan to become linked when a later drop supplies its lead.
- `unknown_disposition_events`: derived index of linked disposition events whose code is absent from the workflow catalogue.
- `rejections`, `quality`, and `ingested_drops`: rejected row details, quality counters, and drop idempotency fingerprints.

### PII protection

Fields marked `pii: true` are not stored in plaintext. Customer names and canonical phone numbers use Fernet authenticated encryption. Phone lookup uses a deterministic HMAC-SHA256 digest derived from the separate encryption key, allowing equality matching without storing a plaintext phone. Event JSON stored in the ledger omits the phone; only its HMAC is retained for matching. The encryption key is created as `.pii.key`, excluded from version control, and must be backed up securely. This is application-level encryption at rest; production deployment should use a managed KMS and separate key rotation/access controls.

### Processing decisions

- CSV headers and aliases use the specified lower-case/trim/underscore-or-whitespace normalization.
- Blank rows are skipped. Nonblank row numbers are counted per file.
- Required-field failures and invalid phones reject the row at the first failure in schema order. Invalid optional values become null and increment warnings only for accepted rows.
- Duplicate leads merge by workflow and canonical phone. First-seen batch ID is permanent; later non-null values overwrite existing values. Defaults are applied after merges.
- Drop directories are processed in command order; files are processed by filename. Re-ingesting an unchanged resolved path is a no-op. Reusing that path for changed content is rejected rather than mixing two datasets.
- Every nonempty event line contributes to `events_total`. Invalid JSON/missing event ID contributes to malformed count. Valid event IDs are deduplicated globally before later classification.
- Orphan events remain in the ledger and are re-linked whenever new leads arrive. The orphan index is recalculated from final link state, so quality reports show only currently unresolved events.
- Unknown disposition events are retained in the immutable ledger for audit but excluded from effective-disposition/report calculations. They are counted only after their event can be linked to a valid lead, following the spec's orphan-before-unknown classification order.
- Naive timestamps are interpreted as IST; all report dates and call timestamps are normalized to IST. Comparisons of event instants use timezone-aware datetimes, not string ordering.
- A call is included only when its linked `call.initiated` event exists. A lead's bucket follows the stated precedence: no calls, terminal effective disposition, all calls telephony-failed, otherwise dialed.

## Trade-offs and next steps

The core solution favors correctness and a small operational footprint over the large-scale performance stretch goal. Report aggregation currently runs in Python over indexed SQLite tables. For sustained high volume, I would move daily and lead aggregations into SQL, batch inserts, and measure query plans on the large generator scale. For 100k leads/day, I would run ingestion as scheduled idempotent jobs, persist per-file checksums and job status, use transactional checkpoints, alert on failed batches, and support backfills by replaying immutable source drops into a fresh or versioned database. Key management should move to KMS, and database backups must be encrypted.

## Validation performed

- `python -m unittest -v tests`: 5 tests passed.
- Generated a seed-42 small dataset, ingested `drop_1` then `drop_2`, and generated all five report files.
- Re-ingested `drop_2`; the CLI correctly reported it as already ingested and made no changes.

The evaluator should run the same commands with its own generated seed and a fresh database/key.
