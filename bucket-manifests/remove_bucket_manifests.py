#!/opt/splunk/bin/python
"""
Splunk Bucket Manifest Cleaner

Reads a CSV file containing a list of bucket IDs (bid) in the format
<index>~<seqno>~<peer_guid>, resolves each bucket's directory on disk,
moves the entire bucket folder to a backup directory, and removes the
matching bucket line from the tier-level .bucketManifest file.

The tier-level .bucketManifest is built off of the bucket folders, so
removing only the manifest is insufficient — Splunk would rebuild the
same stale entry from the folder. Moving the folder and pruning the
manifest line ensures a clean removal.

Usage:
    $SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifests
    $SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifests --dry-run
    $SPLUNK_HOME/bin/python remove_bucket_manifests.py --csv buckets.csv --backup-dir /tmp/manifests --splunk-home /opt/splunk

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
    Glob across all tiers under $SPLUNK_DB/<index>/<tier>/ looking for
    a directory matching:
      Clustered:  db_*_*_<seqno>_<guid>
      Standalone: db_*_*_<seqno>
    Returns a list of matched Path objects (usually 0 or 1).
    """
    pattern_suffix = f"db_*_*_{seqno}_{guid}" if guid else f"db_*_*_{seqno}"
    matches = []
    for tier in TIERS:
        tier_path = splunk_db / index_name / tier
        candidates = glob.glob(str(tier_path / pattern_suffix))
        matches.extend(Path(c) for c in candidates if Path(c).is_dir())
    return matches


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def prune_manifest_line(manifest_path: Path, bucket_name: str) -> str:
    """
    Remove any line in the tier-level .bucketManifest that references the
    given bucket directory name. Returns one of: "pruned", "absent",
    "missing" (manifest file not present).

    The manifest is rewritten in-place via a temp file + atomic replace to
    avoid leaving a half-written file if interrupted.
    """
    if not manifest_path.exists():
        return "missing"

    try:
        with open(manifest_path, "r") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise OSError(f"cannot read {manifest_path}: {exc}")

    kept = [ln for ln in lines if bucket_name not in ln]
    if len(kept) == len(lines):
        return "absent"

    tmp_path = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
    try:
        with open(tmp_path, "w") as fh:
            fh.writelines(kept)
        os.replace(str(tmp_path), str(manifest_path))
    except OSError as exc:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise OSError(f"cannot rewrite {manifest_path}: {exc}")

    return "pruned"


def process_buckets(bids: list, splunk_db: Path, backup_dir: Path, dry_run: bool) -> dict:
    """
    Iterate over parsed bid entries, resolve the bucket directory, move
    the entire bucket folder to backup_dir, and prune the matching line
    from the tier-level .bucketManifest.

    Returns a summary dict.
    """
    summary = {
        "total":         0,
        "moved":         0,
        "manifest_pruned": 0,
        "not_found":     0,
        "ambiguous":     0,
        "errors":        0,
        "skipped":       0,
    }

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
        tier_manifest = bucket_dir.parent / ".bucketManifest"

        # --- act ---
        if dry_run:
            log_dryrun(f"Would move: {bucket_dir} -> {backup_dir}/{bucket_dir.name}")
            if tier_manifest.exists():
                log_dryrun(f"Would prune '{bucket_dir.name}' entry from: {tier_manifest}")
            else:
                log_dryrun(f"No tier-level manifest at: {tier_manifest} (nothing to prune)")
            summary["moved"] += 1
            continue

        try:
            dest = backup_dir / bucket_dir.name
            if dest.exists():
                log_warn(
                    f"Line {lineno}: backup destination already exists, skipping: {dest}"
                )
                summary["errors"] += 1
                continue
            shutil.move(str(bucket_dir), str(dest))
            log_success(f"Moved folder: {bucket_dir} -> {dest}")
            summary["moved"] += 1
        except OSError as exc:
            log_error(f"Line {lineno}: failed to move {bucket_dir} — {exc}")
            summary["errors"] += 1
            continue

        try:
            result = prune_manifest_line(tier_manifest, bucket_dir.name)
            if result == "pruned":
                log_success(f"Pruned entry '{bucket_dir.name}' from {tier_manifest}")
                summary["manifest_pruned"] += 1
            elif result == "absent":
                log_info(f"No entry for '{bucket_dir.name}' in {tier_manifest}")
            elif result == "missing":
                log_info(f"No tier-level manifest at: {tier_manifest}")
        except OSError as exc:
            log_error(f"Line {lineno}: {exc}")
            summary["errors"] += 1

    return summary


def print_summary(summary: dict, dry_run: bool) -> None:
    label = "Would move" if dry_run else "Moved folders"
    prune_label = "Would prune manifest lines" if dry_run else "Pruned manifest lines"
    print()
    print(f"{Colors.BOLD}{'=' * 50}{Colors.ENDC}")
    print(f"{Colors.BOLD}Summary{Colors.ENDC}")
    print(f"{'=' * 50}")
    print(f"  Total buckets in CSV : {summary['total']}")
    print(f"  {label:<22}: {summary['moved']}")
    if not dry_run:
        print(f"  {prune_label:<22}: {summary['manifest_pruned']}")
    print(f"  Not found on disk    : {summary['not_found']}")
    print(f"  Ambiguous matches    : {summary['ambiguous']}")
    print(f"  Malformed / skipped  : {summary['skipped']}")
    print(f"  Errors               : {summary['errors']}")
    print(f"{'=' * 50}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Move entire bucket folders for a list of Splunk bucket IDs to a backup directory "
            "and prune the matching bucket lines from the tier-level .bucketManifest. "
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
        help="Directory to move bucket folders into (created if it does not exist).",
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
        help="Print what would be moved/pruned without touching anything.",
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
            "splunkd appears to be running. Moving bucket folders while Splunk "
            "is running can cause search errors or data inconsistency — strongly "
            "consider stopping splunkd before proceeding."
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
