#!/opt/splunk/bin/python
"""
Test HEC Event Generator

Sends a synthetic "freeze skipped for bid=" event to Splunk via HEC so that
find_bucket_manifests.py has something to find in splunkd.log.

The event mimics the real BucketMover log format:
  02-20-2026 11:43:53.188 -0600 INFO BucketMover [3148854 FilesystemOpExecutorWorker-0] - RemoteStorageAsyncFreezer freeze skipped for bid=<bid> since bucket was not stable

The event is written to index=main with sourcetype=splunkd.

Usage:
    $SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN>
    $SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --bid myindex~42
    $SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --count 5
    $SPLUNK_HOME/bin/python generate_test_event.py --token <HEC_TOKEN> --splunk-host 192.168.1.10

Options:
    --token         HEC token (required)
    --bid           Bucket ID to embed (default: auto-generated)
    --count         Number of events to send (default: 1)
    --splunk-host   Splunk host (default: 127.0.0.1)
    --hec-port      HEC port (default: 8088)
    --no-ssl-verify Disable SSL certificate verification (useful for self-signed certs)
"""

import sys
import json
import uuid
import argparse
import subprocess
from datetime import datetime


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    ENDC   = "\033[0m"
    BOLD   = "\033[1m"


def log_info(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.ENDC}  {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[OK]{Colors.ENDC}    {msg}")

def log_warn(msg):
    print(f"{Colors.YELLOW}[WARN]{Colors.ENDC}  {msg}")

def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.ENDC} {msg}")


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def make_bid(index: str = "testindex") -> str:
    """Generate a realistic clustered bid."""
    seqno = 42
    guid = str(uuid.uuid4()).upper()
    return f"{index}~{seqno}~{guid}"


def build_event(bid: str) -> dict:
    """
    Build a HEC JSON payload matching the real BucketMover log format.
    Targeting index=main (HEC cannot write to internal indexes).
    """
    now = datetime.now().astimezone()
    tz_offset = now.strftime("%z")          # e.g. -0600
    timestamp_str = now.strftime(f"%m-%d-%Y %H:%M:%S.%f")[:-3] + f" {tz_offset}"
    unix_ts = now.timestamp()

    raw = (
        f"{timestamp_str} INFO BucketMover [3148854 FilesystemOpExecutorWorker-0] - "
        f"RemoteStorageAsyncFreezer freeze skipped for bid={bid} "
        f"since bucket was not stable"
    )

    return {
        "time":       unix_ts,
        "host":       "test-splunk-host",
        "source":     "splunkd.log",
        "sourcetype": "splunkd",
        "index":      "main",
        "event":      raw,
    }


# ---------------------------------------------------------------------------
# HEC sender
# ---------------------------------------------------------------------------

def send_event(payload: dict, url: str, token: str, verify_ssl: bool) -> None:
    data = json.dumps(payload)
    cmd = [
        "curl", "-s",
        "-X", "POST", url,
        "-H", f"Authorization: Splunk {token}",
        "-H", "Content-Type: application/json",
        "-d", data,
    ]
    if not verify_ssl:
        cmd.append("-k")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"curl failed: {result.stderr.strip()}")

    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"Unexpected HEC response: {result.stdout.strip()}")

    if body.get("text") != "Success":
        raise RuntimeError(f"HEC returned non-success: {result.stdout.strip()}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Send synthetic 'freeze skipped for bid=' events to Splunk via HEC "
            "for use with find_bucket_manifests.py testing."
        )
    )
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument(
        "--token",
        metavar="TOKEN",
        help="HEC token (literal value).",
    )
    token_group.add_argument(
        "--token-file",
        metavar="FILE",
        help="Path to a file containing the HEC token (first line used).",
    )
    parser.add_argument(
        "--bid",
        default=None,
        metavar="BID",
        help=(
            "Bucket ID to embed in the event "
            "(e.g. myindex~42 or myindex~42~GUID). "
            "Default: testindex~42."
        ),
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        metavar="N",
        help="Number of events to send (default: 1).",
    )
    parser.add_argument(
        "--splunk-host",
        default="127.0.0.1",
        metavar="HOST",
        help="Splunk hostname or IP (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--hec-port",
        type=int,
        default=8088,
        metavar="PORT",
        help="HEC port (default: 8088).",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (use for self-signed certs).",
    )
    args = parser.parse_args()

    if args.token_file:
        try:
            with open(args.token_file) as fh:
                token = fh.readline().strip()
            if not token:
                log_error(f"Token file is empty: {args.token_file}")
                sys.exit(1)
        except OSError as exc:
            log_error(f"Cannot read token file: {exc}")
            sys.exit(1)
    else:
        token = args.token

    bid = args.bid or make_bid()
    url = f"https://{args.splunk_host}:{args.hec_port}/services/collector/event"

    log_info(f"HEC endpoint : {url}")
    log_info(f"Bid          : {bid}")
    log_info(f"Events       : {args.count}")
    if args.no_ssl_verify:
        log_warn("SSL verification disabled.")
    print()

    errors = 0
    for i in range(1, args.count + 1):
        payload = build_event(bid)
        try:
            send_event(payload, url, token, verify_ssl=not args.no_ssl_verify)
            log_success(f"Sent event {i}/{args.count}: {payload['event']}")
        except RuntimeError as exc:
            log_error(f"Event {i}/{args.count} failed: {exc}")
            errors += 1

    print()
    if errors:
        log_error(f"{errors}/{args.count} event(s) failed to send.")
        sys.exit(1)
    else:
        log_success(f"All {args.count} event(s) sent to index=main.")
        log_info(
            "To verify: search  index=main \"freeze skipped for bid\"  in Splunk."
        )
        log_info(
            "To find via log parser: "
            f"./find_bucket_manifests.py --output buckets.csv"
        )


if __name__ == "__main__":
    main()
