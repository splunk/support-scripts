#!/bin/bash

# Pull peer URIs from distsearch.conf via btool and extract hostnames
PEERS=$(splunk btool distsearch list --debug | \
    grep 'servers =' | \
    awk -F= '{print $2}' | \
    tr -d '[:space:]' | \
    tr ',' '\n' | \
    sed 's|https\?://||' | \
    cut -d: -f1 | \
    sort -u)

PORT=8089

echo "Testing connectivity to port $PORT on all discovered peers..."
echo

for peer in $PEERS; do
  echo -n "Connecting to $peer:$PORT... "
  timeout 2 bash -c "</dev/tcp/$peer/$PORT" &>/dev/null
  if [ $? -eq 0 ]; then
    echo "Success"
  else
    echo "Failed"
  fi
done
