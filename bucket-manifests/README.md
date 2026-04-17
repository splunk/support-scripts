# Bucket Manifest Cleaner

A toolkit for identifying and moving stale `.bucketManifest` files from Splunk index buckets. Stale manifests can prevent buckets from being frozen/archived — `find_bucket_manifests.py` locates the affected buckets, `remove_bucket_manifests.py` (Python) or `remove_bucket_manifests.sh` (Bash) moves the manifest files to a backup directory, and `generate_test_event.py` seeds test data via HEC.

## Purpose

When Splunk logs `freeze skipped for bid=<bucket_id>` in `splunkd.log`, it typically indicates a bucket has a stale or corrupt `.bucketManifest` file that is preventing normal freeze/archive lifecycle operations. This toolkit automates the discovery and cleanup process.

## Requirements

- Splunk Enterprise installation
- Splunk's bundled Python interpreter (`$SPLUNK_HOME/bin/python`)
- Linux / macOS
- Read access to `$SPLUNK_HOME/var/log/splunk/` (find script)
- Write access to the index bucket directories (remove script)

## Usage

### Step 1 — Find affected bucket IDs

Parses `splunkd.log*` for `freeze skipped for bid=` entries and writes a deduplicated CSV.

```bash
$SPLUNK_HOME/bin/python find_bucket_manifests.py --output buckets.csv
```

### Step 2 — Review the CSV

```
bid
myindex~35~B5C33FDC-F337-4971-A01E-FE46B75AABE3
_internaldb~42
```

### Step 3 — Dry-run the move

```bash
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup --dry-run
```

### Step 4 — Move the manifest files

**Python (recommended — supports dry-run, SPLUNK_DB resolution, and detailed summary):**

```bash
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup
```

**Bash (simplified — requires `bash`, hardcoded to `/opt/splunk`):**

```bash
./remove_bucket_manifests.sh --csv buckets.csv --backup /tmp/manifest_backup
```

---

## find_bucket_manifests.py

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output FILE` | `buckets.csv` | Path to write the output CSV |
| `--splunk-home PATH` | `$SPLUNK_HOME` or `/opt/splunk` | Splunk installation directory |
| `--log-dir PATH` | `$SPLUNK_HOME/var/log/splunk` | Directory containing `splunkd.log*` files |
| `--index NAME` | *(all)* | Restrict results to this index. Repeatable |
| `--limit N` | *(none)* | Stop after finding N bucket IDs |
| `--debug` | off | Print each log file scanned and each bid found |

### Examples

```bash
# All indices, default log location
$SPLUNK_HOME/bin/python find_bucket_manifests.py --output buckets.csv

# Restrict to one index
$SPLUNK_HOME/bin/python find_bucket_manifests.py --index myindex --output buckets.csv

# Override log directory (e.g. logs shipped elsewhere)
$SPLUNK_HOME/bin/python find_bucket_manifests.py --log-dir /mnt/logs/splunk --output buckets.csv

# Sample — stop after first 10 hits
$SPLUNK_HOME/bin/python find_bucket_manifests.py --limit 10 --output buckets.csv

# Verbose output to diagnose no-results
$SPLUNK_HOME/bin/python find_bucket_manifests.py --debug --output buckets.csv
```

### CSV format (output)

Single column with header `bid`. Bucket IDs follow Splunk's native format:

- **Clustered indexer:** `<index>~<seqno>~<peer_guid>`
- **Standalone indexer:** `<index>~<seqno>`

---

## remove_bucket_manifests.py

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--csv FILE` | *(required)* | CSV file produced by `find_bucket_manifests.py` |
| `--backup-dir PATH` | *(required)* | Directory to move manifest files into (created if it does not exist) |
| `--splunk-home PATH` | `$SPLUNK_HOME` or `/opt/splunk` | Splunk installation directory |
| `--dry-run` | off | Print what would be moved without touching anything |

### Examples

```bash
# Preview moves
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup --dry-run

# Live run
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup

# Non-default Splunk install
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup --splunk-home /opt/splunk2
```

### Example output

```
[INFO]  SPLUNK_HOME : /opt/splunk
[INFO]  SPLUNK_DB   : /opt/splunk/var/lib/splunk
[INFO]  Backup dir  : /tmp/manifest_backup

[INFO]  Loaded 3 bucket ID(s) from buckets.csv

[OK]    Moved: .../myindex/db/db_1746000000_1745000000_35_B5C33FDC-.../.bucketManifest -> /tmp/manifest_backup/db_..._35_..._.bucketManifest
[OK]    Moved: .../internaldb/db/db_1746000000_1745000000_42/.bucketManifest -> /tmp/manifest_backup/db_..._42_.bucketManifest
[INFO]  No manifest present (already clean): ...

==================================================
Summary
==================================================
  Total buckets in CSV : 3
  Moved                : 2
  Already clean        : 1
  Not found on disk    : 0
  Ambiguous matches    : 0
  Malformed / skipped  : 0
  Errors               : 0
==================================================
```

---

## generate_test_event.py

Sends a synthetic `freeze skipped for bid=` log line to Splunk via HEC, targeting `index=_splunkd` with `sourcetype=splunkd`. After Splunk flushes it to `splunkd.log`, `find_bucket_manifests.py` will pick it up.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--token TOKEN` | *(required)* | HEC token |
| `--bid BID` | `testindex~42` | Bucket ID to embed in the event |
| `--count N` | `1` | Number of events to send |
| `--splunk-host HOST` | `127.0.0.1` | Splunk hostname or IP |
| `--hec-port PORT` | `8088` | HEC port |
| `--no-ssl-verify` | off | Disable SSL certificate verification (use for self-signed certs) |

### Examples

```bash
# Send one event with the default bid
$SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --no-ssl-verify

# Send an event with a specific bid matching a real bucket on disk
$SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --bid _internaldb~42 --no-ssl-verify

# Send multiple events (e.g. to test deduplication in find script)
$SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --bid myindex~7 --count 5 --no-ssl-verify

# Remote Splunk instance
$SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --splunk-host 192.168.1.10 --bid myindex~7
```

### Full lab workflow

```bash
# 1. Send a test event
$SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --bid _internaldb~42 --no-ssl-verify

# 2. Wait ~30s for Splunk to flush to splunkd.log, then find it
$SPLUNK_HOME/bin/python find_bucket_manifests.py --output buckets.csv

# 3. Verify the CSV, then move the manifests
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup --dry-run
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifest_backup
```

> **Note:** The event lands in `index=_splunkd`. To confirm receipt before running the find script, search `index=_splunkd "freeze skipped for bid"` in Splunk.

---

## remove_bucket_manifests.sh

A simplified Bash alternative to the Python removal script. Copies `.bucketManifest` files to a backup folder then removes the originals. SPLUNK_HOME is hardcoded to `/opt/splunk` and there is no dry-run mode.

### Options

| Option | Description |
|--------|-------------|
| `--csv FILE` | *(required)* CSV file containing bucket IDs, one per line (no header row) |
| `--backup PATH` | *(required)* Directory to copy manifest files into before removal |

### CSV format

The shell script skips blank lines and the `bid` header row, so the CSV produced by `find_bucket_manifests.py` can be passed directly:

```
bid
myindex~35~B5C33FDC-F337-4971-A01E-FE46B75AABE3
_internaldb~42
```

### Examples

```bash
./remove_bucket_manifests.sh --csv buckets.csv --backup /tmp/manifest_backup
```

### Differences from the Python script

| | Python (`remove_bucket_manifests.py`) | Bash (`remove_bucket_manifests.sh`) |
|---|---|---|
| SPLUNK_HOME | Configurable via `--splunk-home` or env | Hardcoded to `/opt/splunk` |
| Backup flag | `--backup-dir` | `--backup` |
| Dry-run | Yes (`--dry-run`) | No |
| CSV header | Required (`bid`) | Skipped automatically |
| Operation | Atomic `shutil.move` | `cp` then `rm` |
| Summary | Detailed per-category count | Per-bucket echo only |

## Notes

- **Two removal options.** Use the Python script for dry-run support, automatic SPLUNK_DB resolution, and a full summary. Use the Bash script for quick runs on standard `/opt/splunk` installs without needing Splunk's Python.

- **Safe while Splunk is running.** Splunk regenerates `.bucketManifest` files automatically; moving them will not cause data loss. The script warns if `splunkd` is detected running, but does not block execution.
- **`SPLUNK_DB` resolution.** The remove script checks the `SPLUNK_DB` env var, then `splunk-launch.conf`, then falls back to `$SPLUNK_HOME/var/lib/splunk` — consistent with how Splunk itself resolves the path.
- **Bucket tiers searched.** `db/`, `colddb/`, and `thaweddb/` are all scanned. `frozendb` is excluded as frozen buckets are not managed by Splunk's lifecycle.
- **Ambiguity guard.** If more than one directory matches a given bucket ID, that row is skipped and logged as a warning rather than guessing.
- **Backup file naming.** Each moved file is prefixed with the bucket directory name (e.g. `db_<latest>_<earliest>_<seqno>_.bucketManifest`) to prevent collisions when buckets across different indices share the same sequence number.
- **Exit code.** `remove_bucket_manifests.py` exits with code `1` if any move operations fail, suitable for use in automation pipelines.
