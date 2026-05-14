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

            bucket_basename="$(basename "$bucket_dir")"
            tier_manifest="${tier_path}/.bucketManifest"

            mkdir -p "$BACKUP_ROOT"
            dest="${BACKUP_ROOT}/${bucket_basename}"

            if [[ -e "$dest" ]]; then
                echo "[WARN]  Backup destination already exists, skipping: ${dest}"
                found=1
                continue
            fi

            if mv "$bucket_dir" "$dest"; then
                echo "[OK]    Moved folder: ${bucket_dir} -> ${dest}"
            else
                echo "[ERROR] Failed to move folder: ${bucket_dir}"
                found=1
                continue
            fi

            if [[ -f "$tier_manifest" ]]; then
                tmp_manifest="${tier_manifest}.tmp.$$"
                if grep -v -F "$bucket_basename" "$tier_manifest" > "$tmp_manifest"; then
                    if ! cmp -s "$tier_manifest" "$tmp_manifest"; then
                        mv "$tmp_manifest" "$tier_manifest"
                        echo "[OK]    Pruned entry '${bucket_basename}' from ${tier_manifest}"
                    else
                        rm -f "$tmp_manifest"
                        echo "[INFO]  No entry for '${bucket_basename}' in ${tier_manifest}"
                    fi
                else
                    rm -f "$tmp_manifest"
                    echo "[ERROR] Failed to rewrite ${tier_manifest}"
                fi
            else
                echo "[INFO]  No tier-level manifest at: ${tier_manifest}"
            fi

            found=1
        done
    done

    if [[ $found -eq 0 ]]; then
        echo "[WARN]  Bucket not found on disk for bid=${bucket_id}"
    fi
done < "$BUCKET_LIST_FILE"
