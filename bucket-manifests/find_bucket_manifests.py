#!/opt/splunk/bin/python
"""
Splunk Bucket Manifest Finder

By default, parses splunkd.log* for buckets whose freeze was skipped
("freeze skipped for bid=") and writes a CSV of their IDs suitable for
use with remove_bucket_manifests.py.

Use --scan for filesystem-based discovery (walks SPLUNK_DB looking for
buckets that actually have a .bucketmanifest file on disk).

Usage:
    # Default: extract skipped-freeze bids from splunkd.log
    $SPLUNK_HOME/bin/python find_bucket_manifests.py --output buckets.csv

    # Restrict to one index or override the log directory
    $SPLUNK_HOME/bin/python find_bucket_manifests.py --index myindex --output buckets.csv
    $SPLUNK_HOME/bin/python find_bucket_manifests.py --log-dir /path/to/logs --output buckets.csv

    # Filesystem scan mode (lab/demo)
    $SPLUNK_HOME/bin/python find_bucket_manifests.py --scan --output buckets.csv

Options:
    --splunk-home   PATH   SPLUNK_HOME directory (default: $SPLUNK_HOME or /opt/splunk)
    --index         NAME   Restrict results to this index (repeatable)
    --limit         N      Stop after finding N matching buckets
    --output        FILE   Write CSV to this file (default: buckets.csv)
    --log-dir       PATH   Directory containing splunkd.log* (default: $SPLUNK_HOME/var/log/splunk)
    --scan                 Walk SPLUNK_DB for .bucketmanifest files instead of parsing logs
    --debug                Print detailed diagnostic info during the search
"""

import os
import sys
import csv
import argparse
import glob
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Terminal colours  (same palette as remove_bucket_manifests.py)
# ---------------------------------------------------------------------------

class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    ENDC   = "\033[0m"


def log_info(msg: str) -> None:
    print(f"{Colors.BLUE}[INFO]{Colors.ENDC}  {msg}", file=sys.stderr)


def log_warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[WARN]{Colors.ENDC}  {msg}", file=sys.stderr)


def log_error(msg: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.ENDC} {msg}", file=sys.stderr)


def log_success(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.ENDC}    {msg}", file=sys.stderr)


def log_debug(msg: str) -> None:
    print(f"{Colors.CYAN}[DEBUG]{Colors.ENDC} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# SPLUNK_DB resolution  (mirrors remove_bucket_manifests.py)
# ---------------------------------------------------------------------------

TIERS = ("db", "colddb", "thaweddb")

# Standalone warm buckets:  db_<latest>_<earliest>_<seqno>
# Clustered warm buckets:   db_<latest>_<earliest>_<seqno>_<peer_guid>
BUCKET_DIR_RE = re.compile(
    r"^db_\d+_\d+_(?P<seqno>\d+)(?:_(?P<guid>[0-9A-Fa-f\-]+))?$"
)


def resolve_splunk_db(splunk_home: Path) -> Path:
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
# Discovery
# ---------------------------------------------------------------------------

def iter_manifests(splunk_db: Path, index_filter: list, limit: int, debug: bool = False):
    """
    Yield (index_name, seqno, guid) tuples for every bucket directory that
    contains a .bucketmanifest file.

    Stops after `limit` results (0 = unlimited).
    """
    found = 0

    # Determine which index directories to walk
    if index_filter:
        index_dirs = [splunk_db / name for name in index_filter]
    else:
        try:
            index_dirs = sorted(
                p for p in splunk_db.iterdir() if p.is_dir()
            )
        except OSError as exc:
            log_error(f"Cannot list SPLUNK_DB: {exc}")
            sys.exit(1)

    if debug:
        log_debug(f"Index directories to scan ({len(index_dirs)}): "
                  + ", ".join(d.name for d in index_dirs))

    for index_dir in index_dirs:
        if not index_dir.is_dir():
            log_warn(f"Index directory not found, skipping: {index_dir}")
            continue

        index_name = index_dir.name

        for tier in TIERS:
            tier_dir = index_dir / tier
            if not tier_dir.is_dir():
                if debug:
                    log_debug(f"Tier not present, skipping: {tier_dir}")
                continue

            try:
                bucket_dirs = sorted(
                    p for p in tier_dir.iterdir() if p.is_dir()
                )
            except OSError as exc:
                log_warn(f"Cannot list tier directory {tier_dir}: {exc}")
                continue

            if debug:
                log_debug(f"{tier_dir}: {len(bucket_dirs)} sub-director{'y' if len(bucket_dirs) == 1 else 'ies'} found")

            for bucket_dir in bucket_dirs:
                m = BUCKET_DIR_RE.match(bucket_dir.name)
                if not m:
                    if debug:
                        manifest_marker = " [has .bucketmanifest]" if (bucket_dir / ".bucketmanifest").exists() else ""
                        log_debug(f"  No regex match: {bucket_dir.name}{manifest_marker}")
                    continue  # not a standard bucket directory

                manifest = bucket_dir / ".bucketmanifest"
                if not manifest.exists():
                    if debug:
                        log_debug(f"  Matched, no manifest: {bucket_dir.name}")
                    continue

                seqno = m.group("seqno")
                guid  = m.group("guid") or ""  # None on standalone

                yield index_name, seqno, guid
                found += 1

                if limit and found >= limit:
                    return


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def parse_splunkd_logs(log_dir: Path, index_filter: list, limit: int, debug: bool) -> list:
    """
    Scan splunkd.log* files for lines containing 'freeze skipped for bid='
    and return a deduplicated, insertion-ordered list of bid strings.
    Equivalent to:
        grep 'freeze skipped for bid=' splunkd.log* \
            | sed -r 's/.*bid=([^[:space:]]+).*/\\1/' | sort | uniq
    """
    BID_RE = re.compile(r"bid=(\S+)")
    log_files = sorted(glob.glob(str(log_dir / "splunkd.log*")))

    if not log_files:
        log_warn(f"No splunkd.log* files found in: {log_dir}")
        return []

    if debug:
        log_debug(
            f"Log files to scan ({len(log_files)}): "
            + ", ".join(Path(f).name for f in log_files)
        )

    bids_seen: set = set()
    bids: list = []

    for log_file in log_files:
        if debug:
            log_debug(f"Scanning: {log_file}")
        try:
            with open(log_file, "r", errors="replace") as fh:
                for line in fh:
                    if "freeze skipped for bid=" not in line:
                        continue
                    m = BID_RE.search(line)
                    if not m:
                        continue
                    bid = m.group(1)
                    if index_filter and bid.split("~")[0] not in index_filter:
                        continue
                    if bid not in bids_seen:
                        bids_seen.add(bid)
                        bids.append(bid)
                        if limit and len(bids) >= limit:
                            return bids
        except OSError as exc:
            log_warn(f"Cannot read {log_file}: {exc}")

    return bids


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Find Splunk bucket IDs whose freeze was skipped (from splunkd.log) and "
            "write a CSV suitable for use with remove_bucket_manifests.py. "
            "Use --scan for filesystem-based discovery instead."
        )
    )
    parser.add_argument(
        "--splunk-home",
        default=os.environ.get("SPLUNK_HOME", "/opt/splunk"),
        metavar="PATH",
        help="Path to SPLUNK_HOME (default: $SPLUNK_HOME or /opt/splunk).",
    )
    parser.add_argument(
        "--index",
        action="append",
        metavar="NAME",
        dest="indices",
        default=[],
        help="Restrict results to this index (repeatable). Default: all indices.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Stop after finding N matching buckets (default: no limit).",
    )
    parser.add_argument(
        "--output",
        default="buckets.csv",
        metavar="FILE",
        help="Output CSV file path (default: buckets.csv).",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        metavar="PATH",
        help="Directory containing splunkd.log* files (default: $SPLUNK_HOME/var/log/splunk).",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help=(
            "Walk SPLUNK_DB directories for buckets that have a .bucketmanifest file "
            "instead of parsing splunkd.log (lab/demo mode)."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed diagnostic info during the search.",
    )
    args = parser.parse_args()

    splunk_home = Path(args.splunk_home)
    output_path = Path(args.output)

    if not splunk_home.is_dir():
        log_error(f"SPLUNK_HOME does not exist or is not a directory: {splunk_home}")
        sys.exit(1)

    log_info(f"SPLUNK_HOME : {splunk_home}")
    if args.indices:
        log_info(f"Index filter: {', '.join(args.indices)}")
    if args.limit:
        log_info(f"Limit       : {args.limit}")
    log_info(f"Output      : {output_path}")
    print(file=sys.stderr)

    count = 0

    if args.scan:
        # --- Filesystem walk mode (lab/demo) ---
        splunk_db = resolve_splunk_db(splunk_home)
        log_info(f"Mode        : filesystem scan")
        log_info(f"SPLUNK_DB   : {splunk_db}")
        if not splunk_db.is_dir():
            log_error(f"SPLUNK_DB directory does not exist: {splunk_db}")
            sys.exit(1)
        print(file=sys.stderr)

        with open(output_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["bid"])
            for index_name, seqno, guid in iter_manifests(
                splunk_db, args.indices, args.limit, debug=args.debug
            ):
                # Clustered: index~seqno~guid  |  Standalone: index~seqno
                bid = f"{index_name}~{seqno}~{guid}" if guid else f"{index_name}~{seqno}"
                writer.writerow([bid])
                log_info(f"Found: {bid}")
                count += 1

    else:
        # --- Log parsing mode (default) ---
        log_dir = (
            Path(args.log_dir)
            if args.log_dir
            else splunk_home / "var" / "log" / "splunk"
        )
        log_info(f"Mode        : splunkd.log parse")
        log_info(f"Log dir     : {log_dir}")
        if not log_dir.is_dir():
            log_error(f"Log directory does not exist: {log_dir}")
            sys.exit(1)
        print(file=sys.stderr)

        bids = parse_splunkd_logs(log_dir, args.indices, args.limit, debug=args.debug)

        with open(output_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["bid"])
            for bid in bids:
                writer.writerow([bid])
                log_info(f"Found: {bid}")
                count += 1

    print(file=sys.stderr)
    if count == 0:
        log_warn("No matching bucket IDs found.")
    else:
        log_success(f"Wrote {count} bucket ID(s) to {output_path}")


if __name__ == "__main__":
    main()
