#!/bin/bash
#usage send job to background: nohup ./pstack_threads.sh &

# Check if pstack is available
if ! command -v pstack &> /dev/null; then
    echo "ERROR: pstack command not found. Please install gdb or pstack." >&2
    exit 1
fi

OUTPUT_DIR=/tmp
SPLUNK_HOME=/opt/splunk
mkdir -p "$OUTPUT_DIR"
SAMPLE_PERIOD=1

while true
do
    # Read splunkd PID
    if [ ! -f "$SPLUNK_HOME/var/run/splunk/splunkd.pid" ]; then
        echo "WARNING: splunkd.pid file not found. Waiting..." >&2
        sleep "$SAMPLE_PERIOD"
        continue
    fi

    pid=$(head -1 "$SPLUNK_HOME/var/run/splunk/splunkd.pid" 2>/dev/null)

    # Validate PID
    if [ -z "$pid" ] || ! [[ "$pid" =~ ^[0-9]+$ ]]; then
        echo "WARNING: Invalid PID '$pid'. Waiting..." >&2
        sleep "$SAMPLE_PERIOD"
        continue
    fi

    # Check if process exists
    if [ ! -f "/proc/$pid/status" ]; then
        echo "WARNING: Process $pid not running. Waiting..." >&2
        sleep "$SAMPLE_PERIOD"
        continue
    fi

    # Get thread count
    threads=$(cat "/proc/$pid/status" 2>/dev/null | grep Threads | awk '{print $2}')

    # Check if thread count is valid
    if [ -z "$threads" ] || ! [[ "$threads" =~ ^[0-9]+$ ]]; then
        echo "WARNING: Could not read thread count for PID $pid. Waiting..." >&2
        sleep "$SAMPLE_PERIOD"
        continue
    fi

    # Collect pstack if threshold exceeded
    if [ "$threads" -gt 500 ]; then
        output_file="$OUTPUT_DIR/pstack_splunkd-$pid-$threads-$(date +%s).out"
        if pstack "$pid" > "$output_file" 2>&1; then
            echo "Collected pstack: $output_file (threads=$threads)"
        else
            echo "ERROR: Failed to collect pstack for PID $pid" >&2
        fi
    fi

    sleep "$SAMPLE_PERIOD"
done
