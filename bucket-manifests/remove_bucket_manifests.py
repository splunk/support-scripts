#!/opt/splunk/bin/python
"""
Splunk Bucket Manifest Cleaner

Reads a CSV file containing a list of bucket IDs (bid) in the format
<index>~<seqno>~<peer_guid>, resolves each bucket's directory on disk,
moves the entire bucket directory to a backup location, and removes
the corresponding entry from the index-level manifest file.

Usage:
    $SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/bucket_backup
    $SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/bucket_backup --dry-run
    $SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/bucket_backup --splunk-home /opt/splunk

CSV format (single column, header required):
    bid
    myindex~35~B5C33FDC-F337-4971-A01E-FE46B75AABE3   (clustered)
    myindex~35                                          (standalone)
    ...
"""

import os
import sys
import csv
import argparse
import glob
import re
import shutil
import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    ENDC   = "\033[0m"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_info(msg: str) -> None:
    print(f"{Colors.BLUE}[INFO]{Colors.ENDC}  {msg}")


def log_success(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.ENDC}    {msg}")


def log_warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[WARN]{Colors.ENDC}  {msg}")


def log_error(msg: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.ENDC} {msg}")


def log_dryrun(msg: str) -> None:
    print(f"{Colors.CYAN}[DRY-RUN]{Colors.ENDC} {msg}")


# ---------------------------------------------------------------------------
# Splunk DB resolution  (mirrors kv_cert_verifier.py pattern)
# ---------------------------------------------------------------------------

TIERS = ("db", "colddb", "thaweddb")


def resolve_splunk_db(splunk_home: Path) -> Path:
    """
    Determine SPLUNK_DB from (in order):
      1. SPLUNK_DB environment variable
      2. splunk-launch.conf
      3. Default: $SPLUNK_HOME/var/lib/splunk
    """
    env_val = os.environ.get("SPLUNK_DB", "").strip()
    if env_val:
        return Path(env_val)

    launch_conf = splunk_home / "etc" / "splunk-launch.conf"
    if launch_conf.exists():
        try:
            with open(launch_conf, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("SPLUNK_DB") and "=" in line:
                        val = line.split("=", 1)[1].strip()
                        val = val.replace("$SPLUNK_HOME", str(splunk_home))
                        if val:
                            return Path(val)
        except OSError:
            pass

    return splunk_home / "var" / "lib" / "splunk"


# ---------------------------------------------------------------------------
# Splunk-running check
# ---------------------------------------------------------------------------

def splunkd_is_running() -> bool:
    """Return True if a splunkd process is detected."""
    try:
        output = subprocess.check_output(
            ["pgrep", "-x", "splunkd"],
            stderr=subprocess.DEVNULL
        )
        return bool(output.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def parse_csv(csv_path: Path) -> list:
    """
    Parse the CSV file and return a list of raw bid strings.
    Expects a single column with header 'bid'.
    """
    bids = []
    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)

        if reader.fieldnames is None or "bid" not in reader.fieldnames:
            log_error(
                f"CSV file '{csv_path}' is missing required 'bid' column header."
            )
            sys.exit(1)

        for lineno, row in enumerate(reader, start=2):
            bid = row.get("bid", "").strip()
            if bid:
                bids.append((lineno, bid))

    return bids


# ---------------------------------------------------------------------------
# Bucket resolution
# ---------------------------------------------------------------------------

def parse_bid(bid: str):
    """
    Parse a bucket ID of the form:
      Clustered:  <index>~<seqno>~<peer_guid>
      Standalone: <index>~<seqno>
    Returns (index, seqno, guid) where guid may be empty string.
    Raises ValueError on malformed input.
    """
    parts = bid.split("~")
    if len(parts) == 2:
        index_name, seqno = parts
        guid = ""
    elif len(parts) == 3:
        index_name, seqno, guid = parts
    else:
        raise ValueError(
            f"Expected 2 or 3 '~'-delimited segments, got {len(parts)}: '{bid}'"
        )
    if not index_name or not seqno:
        raise ValueError(f"One or more empty segments in bid: '{bid}'")

    # Validate each segment to prevent path traversal.
    # Index names: alphanumeric, hyphens, underscores, dots (Splunk convention).
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", index_name):
        raise ValueError(f"Invalid characters in index name: '{index_name}'")
    # Sequence number: digits only.
    if not re.fullmatch(r"\d+", seqno):
        raise ValueError(f"Invalid sequence number (digits only): '{seqno}'")
    # GUID: hex digits and hyphens only (may be empty for standalone).
    if guid and not re.fullmatch(r"[0-9A-Fa-f\-]+", guid):
        raise ValueError(f"Invalid GUID format: '{guid}'")
    return index_name, seqno, guid


def find_bucket_dir(splunk_db: Path, index_name: str, seqno: str, guid: str) -> list:
    """
    Find bucket directories matching the given index, seqno, and optional guid.
    Searches in db/, colddb/, and thaweddb/ tiers.
    Returns a list of matching Path objects.
    """
    matches = []

    for tier in TIERS:
        index_dir = splunk_db / index_name / tier
        if not index_dir.exists():
            continue

        # Pattern: db_<latest>_<earliest>_<seqno>[_<guid>]
        # The guid is optional for standalone deployments
        if guid:
            pattern = f"db_*_*_{seqno}_{guid}"
        else:
            pattern = f"db_*_*_{seqno}"

        # Use glob to find matching directories
        for bucket_dir in index_dir.glob(pattern):
            if bucket_dir.is_dir():
                matches.append(bucket_dir)

    return matches


def update_index_manifest(
    splunk_db: Path, index_name: str, backup_dir: Path, dry_run: bool
) -> tuple[bool, bool]:
    """
    Update the index-level manifest file to remove entries for buckets that have been moved.
    Looks for manifest files in each tier (db, colddb, thaweddb) under the index directory.

    Returns (manifest_updated, manifest_found).
    """
    manifest_updated = False
    manifest_found = False

    for tier in TIERS:
        manifest_path = splunk_db / index_name / tier / ".bucketManifest"
        if not manifest_path.exists():
            continue

        manifest_found = True

        try:
            # Read the manifest file
            with open(manifest_path, "r") as f:
                lines = f.readlines()

            # Filter out lines that reference moved buckets
            # Manifest lines typically contain bucket directory names
            original_count = len(lines)
            filtered_lines = []

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    filtered_lines.append(line)
                    continue

                # Check if this line references a bucket that was moved
                bucket_moved = False
                for backup_item in backup_dir.iterdir():
                    if backup_item.is_dir() and backup_item.name in stripped:
                        bucket_moved = True
                        break

                if not bucket_moved:
                    filtered_lines.append(line)

            # Write back the filtered manifest if it changed
            if len(filtered_lines) != original_count:
                if dry_run:
                    log_dryrun(
                        f"Would update {manifest_path}: {original_count} -> {len(filtered_lines)} lines"
                    )
                else:
                    with open(manifest_path, "w") as f:
                        f.writelines(filtered_lines)
                    log_info(
                        f"Updated {manifest_path}: removed {original_count - len(filtered_lines)} bucket entries"
                    )
                manifest_updated = True

        except Exception as exc:
            log_error(f"Failed to update manifest {manifest_path}: {exc}")
            raise

    return manifest_updated, manifest_found


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def process_buckets(bids: list, splunk_db: Path, backup_dir: Path, dry_run: bool) -> dict:
    """
    Iterate over parsed bid entries, resolve the bucket directory, move
    the entire bucket directory to backup_dir, and remove the corresponding
    entry from the index-level manifest file.

    Returns a summary dict.
    """
    summary = {
        "total":         0,
        "moved":         0,
        "already_clean": 0,
        "not_found":     0,
        "ambiguous":     0,
        "errors":        0,
        "skipped":       0,
        "manifest_updated": 0,
        "manifest_errors": 0,
    }

    # Track which indices we've processed to avoid redundant manifest updates
    processed_indices = set()

    for lineno, bid in bids:
        summary["total"] += 1

        # --- parse ---
        try:
            index_name, seqno, guid = parse_bid(bid)
        except ValueError as exc:
            log_warn(f"Line {lineno}: skipping malformed bid — {exc}")
            summary["skipped"] += 1
            continue

        # --- resolve ---
        matches = find_bucket_dir(splunk_db, index_name, seqno, guid)

        if len(matches) == 0:
            log_warn(f"Line {lineno}: bucket not found on disk: {bid}")
            summary["not_found"] += 1
            continue

        if len(matches) > 1:
            log_warn(
                f"Line {lineno}: ambiguous — {len(matches)} directories matched "
                f"for {bid}; skipping to avoid incorrect removal:"
            )
            for m in matches:
                log_warn(f"  {m}")
            summary["ambiguous"] += 1
            continue

        bucket_dir = matches[0]

        # --- act ---
        if dry_run:
            log_dryrun(f"Would move bucket directory: {bucket_dir} -> {backup_dir}/")
            summary["moved"] += 1
        else:
            try:
                # Move the entire bucket directory to backup
                dest = backup_dir / bucket_dir.name
                shutil.move(str(bucket_dir), str(dest))
                log_success(f"Moved bucket directory: {bucket_dir} -> {dest}")
                summary["moved"] += 1

                # Track this index for manifest cleanup
                processed_indices.add(index_name)

            except OSError as exc:
                log_error(f"Line {lineno}: failed to move bucket directory {bucket_dir} — {exc}")
                summary["errors"] += 1

    # Update index-level manifests for processed indices
    for index_name in processed_indices:
        try:
            updated, found = update_index_manifest(
                splunk_db, index_name, backup_dir, dry_run
            )
            if updated:
                summary["manifest_updated"] += 1
                if not dry_run:
                    log_success(f"Updated manifest for index: {index_name}")
                else:
                    log_dryrun(f"Would update manifest for index: {index_name}")
            elif found:
                log_info(f"No manifest entries needed updating for index: {index_name}")
            else:
                log_info(f"No manifest file found for index: {index_name}; skipping manifest cleanup")
        except Exception as exc:
            log_error(f"Failed to update manifest for index {index_name}: {exc}")
            summary["manifest_errors"] += 1

    return summary


def print_summary(summary: dict, dry_run: bool) -> None:
    label = "Would move" if dry_run else "Moved"
    manifest_label = "Would update" if dry_run else "Updated"
    print()
    print(f"{Colors.BOLD}{'=' * 50}{Colors.ENDC}")
    print(f"{Colors.BOLD}Summary{Colors.ENDC}")
    print(f"{'=' * 50}")
    print(f"  Total buckets in CSV    : {summary['total']}")
    print(f"  {label} bucket dirs      : {summary['moved']}")
    print(f"  {manifest_label} manifests   : {summary['manifest_updated']}")
    print(f"  Not found on disk       : {summary['not_found']}")
    print(f"  Ambiguous matches       : {summary['ambiguous']}")
    print(f"  Malformed / skipped     : {summary['skipped']}")
    print(f"  Errors                  : {summary['errors']}")
    print(f"  Manifest update errors  : {summary['manifest_errors']}")
    print(f"{'=' * 50}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Move .bucketManifest files for a list of Splunk bucket IDs to a backup directory. "
            "Bucket IDs must follow the format <index>~<seqno> or <index>~<seqno>~<peer_guid>."
        )
    )
    parser.add_argument(
        "--csv",
        required=True,
        metavar="FILE",
        help="Path to CSV file with a 'bid' column.",
    )
    parser.add_argument(
        "--backup-dir",
        required=True,
        metavar="PATH",
        help="Directory to move .bucketManifest files into (created if it does not exist).",
    )
    parser.add_argument(
        "--splunk-home",
        default=os.environ.get("SPLUNK_HOME", "/opt/splunk"),
        metavar="PATH",
        help="Path to SPLUNK_HOME (default: $SPLUNK_HOME or /opt/splunk).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be moved without touching anything.",
    )
    args = parser.parse_args()

    splunk_home = Path(args.splunk_home)
    csv_path    = Path(args.csv)
    backup_dir  = Path(args.backup_dir)

    # --- validate inputs ---
    if not splunk_home.is_dir():
        log_error(f"SPLUNK_HOME does not exist or is not a directory: {splunk_home}")
        sys.exit(1)

    if not csv_path.is_file():
        log_error(f"CSV file not found: {csv_path}")
        sys.exit(1)

    # --- create backup dir ---
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log_error(f"Cannot create backup directory '{backup_dir}': {exc}")
        sys.exit(1)

    # --- resolve SPLUNK_DB ---
    splunk_db = resolve_splunk_db(splunk_home)
    log_info(f"SPLUNK_HOME : {splunk_home}")
    log_info(f"SPLUNK_DB   : {splunk_db}")
    log_info(f"Backup dir  : {backup_dir}")
    if not splunk_db.is_dir():
        log_error(f"SPLUNK_DB directory does not exist: {splunk_db}")
        sys.exit(1)

    # --- splunkd running warning ---
    if splunkd_is_running():
        log_warn(
            "splunkd appears to be running. Moving .bucketManifest files while "
            "Splunk is running is generally safe — Splunk will regenerate them — "
            "but verify this is intentional before proceeding."
        )

    if args.dry_run:
        log_info("Dry-run mode enabled — no files will be moved.")

    print()

    # --- parse CSV ---
    bids = parse_csv(csv_path)
    log_info(f"Loaded {len(bids)} bucket ID(s) from {csv_path}")
    print()

    # --- process ---
    summary = process_buckets(bids, splunk_db, backup_dir, dry_run=args.dry_run)
    print_summary(summary, dry_run=args.dry_run)

    if summary["errors"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
