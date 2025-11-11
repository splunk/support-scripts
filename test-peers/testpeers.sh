#!/bin/bash

# NOTE: This script requires bash (not sh) due to /dev/tcp usage

# Check if splunk command is available
if ! command -v splunk >/dev/null 2>&1; then
  echo "Error: 'splunk' command not found in PATH."
  echo "Ensure Splunk is installed and the splunk binary is in your PATH, or run from \$SPLUNK_HOME/bin"
  exit 1
fi

# Pull peer URIs from distsearch.conf via btool and extract hostnames
PEERS=$(splunk btool distsearch list --debug 2>/dev/null | \
    grep 'servers =' | \
    awk -F= '{print $2}' | \
    tr -d '[:space:]' | \
    tr ',' '\n' | \
    sed 's|https\?://||' | \
    cut -d: -f1 | \
    sort -u)

# Check if any peers were discovered
if [ -z "$PEERS" ]; then
  echo "No search peers found in distsearch.conf"
  echo "This script requires distributed search to be configured."
  exit 2
fi

PORT=8089
FAILED_COUNT=0
SUCCESS_COUNT=0

echo "Testing connectivity to port $PORT on all discovered peers..."
echo

for peer in $PEERS; do
  echo -n "Connecting to $peer:$PORT... "
  # Using /dev/tcp for connection testing (bash-specific feature)
  timeout 2 bash -c "</dev/tcp/$peer/$PORT" &>/dev/null
  if [ $? -eq 0 ]; then
    echo "Success"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    echo "Failed"
    FAILED_COUNT=$((FAILED_COUNT + 1))
  fi
done

echo
echo "Results: $SUCCESS_COUNT succeeded, $FAILED_COUNT failed"

# Exit with non-zero if any peers failed
if [ "$FAILED_COUNT" -gt 0 ]; then
  exit 3
fi
