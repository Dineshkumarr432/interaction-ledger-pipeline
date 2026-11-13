# Interaction Ledger & Reporting Pipeline

Python 3.10+ implementation of Assignment A. It uses SQLite for durable storage and Fernet authenticated encryption for PII. The lead and event processing is schema-driven and supports the two supplied workflows.

## Quick start (Windows PowerShell)

```powershell
cd path\to\interaction-ledger-pipeline
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools\generate_data.py --seed 42 --scale small --out .data
python pipeline.py ingest .data\drop_1
python pipeline.py ingest .data\drop_2
python pipeline.py report --out reports
```

The generator is included for reproducible local testing. Do not submit generated `.data/` files. The evaluator can supply new drops generated with a different seed.

## Commands

```text
python pipeline.py ingest <drop-directory>
python pipeline.py report --out <directory>
```

Optional global options (must appear before the command):

```text
python pipeline.py --db path/to/state.sqlite3 --key path/to/pii.key ingest data/drop_1
```

The first run creates `.pii.key`. Keep it private and back it up securely; losing it makes encrypted PII unreadable. Never commit the key or database. The database is created automatically. Re-ingesting the same resolved drop path with unchanged contents is a no-op. If a path is reused with different contents, the pipeline stops and asks for a fresh database so old and new datasets cannot be silently mixed.

## Output

`report --out reports` writes exactly these files:

- `batch_summary.csv`
- `daily_overview.csv`
- `lead_report.csv`
- `rejections.csv`
- `data_quality.json`

## Tests

```powershell
python -m unittest -v tests
```

The test suite covers Indian phone normalization, invalid phones, day-first date parsing, currency/decimal parsing, and bucket precedence. A generated small-scale end-to-end smoke run was also performed with seed 42; both drops ingested and all five reports were generated. Generated data and local database/key files are excluded from the source archive.
