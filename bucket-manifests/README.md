# Bucket Manifest Cleaner

A two-script toolkit for identifying and removing stale `.bucketManifest` files from Splunk index buckets. Stale manifests can prevent buckets from being frozen/archived — `find_bucket_manifests.py` locates the affected buckets, and `remove_bucket_manifests.py` removes the manifest files.

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

### Step 3 — Dry-run the removal

```bash
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --dry-run
```

### Step 4 — Remove the manifest files

```bash
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv
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
| `--splunk-home PATH` | `$SPLUNK_HOME` or `/opt/splunk` | Splunk installation directory |
| `--dry-run` | off | Print what would be removed without deleting anything |

### Examples

```bash
# Preview removals
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --dry-run

# Live run
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv

# Non-default Splunk install
$SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --splunk-home /opt/splunk2
```

### Example output

```
[INFO]  SPLUNK_HOME : /opt/splunk
[INFO]  SPLUNK_DB   : /opt/splunk/var/lib/splunk

[INFO]  Loaded 3 bucket ID(s) from buckets.csv

[OK]    Removed: /opt/splunk/var/lib/splunk/myindex/db/db_1746000000_1745000000_35_B5C33FDC-F337-4971-A01E-FE46B75AABE3/.bucketManifest
[OK]    Removed: /opt/splunk/var/lib/splunk/_internaldb/db/db_1746000000_1745000000_42/.bucketManifest
[INFO]  No manifest present (already clean): ...

==================================================
Summary
==================================================
  Total buckets in CSV : 3
  Removed              : 2
  Already clean        : 1
  Not found on disk    : 0
  Ambiguous matches    : 0
  Malformed / skipped  : 0
  Errors               : 0
==================================================
```

## Notes

- **Safe while Splunk is running.** Splunk regenerates `.bucketManifest` files automatically; removing them will not cause data loss. The script warns if `splunkd` is detected running, but does not block execution.
- **`SPLUNK_DB` resolution.** The remove script checks the `SPLUNK_DB` env var, then `splunk-launch.conf`, then falls back to `$SPLUNK_HOME/var/lib/splunk` — consistent with how Splunk itself resolves the path.
- **Bucket tiers searched.** `db/`, `colddb/`, and `thaweddb/` are all scanned. `frozendb` is excluded as frozen buckets are not managed by Splunk's lifecycle.
- **Ambiguity guard.** If more than one directory matches a given bucket ID, that row is skipped and logged as a warning rather than guessing.
- **Exit code.** `remove_bucket_manifests.py` exits with code `1` if any `os.remove()` calls fail, suitable for use in automation pipelines.
