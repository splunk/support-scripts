#!/bin/bash

# Default values
BUCKET_LIST_FILE=""
BACKUP_ROOT=""

# Function to display usage
usage() {
    echo "Usage: $0 --csv <bucket_ids.csv> --backup <backup_folder>"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --csv)
            shift
            BUCKET_LIST_FILE="$1"
            ;;
        --backup)
            shift
            BACKUP_ROOT="$1"
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
    shift
done

# Validate required arguments
if [[ -z "$BUCKET_LIST_FILE" || -z "$BACKUP_ROOT" ]]; then
    echo "Error: Both --csv and --backup options are required."
    usage
fi

# Check if bucket list file exists
if [[ ! -f "$BUCKET_LIST_FILE" ]]; then
    echo "Error: Bucket list file '$BUCKET_LIST_FILE' does not exist."
    exit 1
fi

SPLUNK_DB="/opt/splunk/var/lib/splunk"
TIERS=("db" "colddb" "thaweddb")

while IFS= read -r bucket_id; do
    # Skip blank lines and the CSV header row
    [[ -z "$bucket_id" || "$bucket_id" == "bid" ]] && continue

    # Extract index name (everything before the first ~)
    index_name="${bucket_id%%~*}"

    # Extract seqno: second ~-delimited field
    remainder="${bucket_id#*~}"
    seqno="${remainder%%~*}"

    # Extract guid: third field if present (empty for standalone indexers)
    guid=""
    if [[ "$remainder" == *"~"* ]]; then
        guid="${remainder#*~}"
    fi

    # Build the glob pattern for the bucket directory name:
    #   clustered:  db_*_*_<seqno>_<guid>
    #   standalone: db_*_*_<seqno>
    if [[ -n "$guid" ]]; then
        bucket_glob="db_*_*_${seqno}_${guid}"
    else
        bucket_glob="db_*_*_${seqno}"
    fi

    found=0
    for tier in "${TIERS[@]}"; do
        tier_path="${SPLUNK_DB}/${index_name}/${tier}"
        [[ -d "$tier_path" ]] || continue

        for bucket_dir in "${tier_path}"/${bucket_glob}; do
            [[ -d "$bucket_dir" ]] || continue

            manifest="${bucket_dir}/.bucketManifest"
            if [[ ! -f "$manifest" ]]; then
                echo "[INFO]  No manifest present (already clean): ${manifest}"
                found=1
                continue
            fi

            # Unique backup filename: prefix with bucket dir basename
            bucket_basename="$(basename "$bucket_dir")"
            mkdir -p "$BACKUP_ROOT"
            dest="${BACKUP_ROOT}/${bucket_basename}_.bucketManifest"

            cp "$manifest" "$dest" && rm -f "$manifest"
            echo "[OK]    Backed up and removed: ${manifest} -> ${dest}"
            found=1
        done
    done

    if [[ $found -eq 0 ]]; then
        echo "[WARN]  Bucket not found on disk for bid=${bucket_id}"
    fi
done < "$BUCKET_LIST_FILE"
