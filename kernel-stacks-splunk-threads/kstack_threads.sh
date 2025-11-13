#!/bin/bash

OUTPUT_DIR="/tmp/kstacks"      # Output directory where kernel stacks will be saved
SPLUNK_HOME="/opt/splunk"      # Splunk installation directory
SAMPLE_PERIOD=1                 # Sampling period in seconds

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root (required to read /proc/*/stack)" >&2
  exit 1
fi

# Check if running on Linux
if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: This script only works on Linux (requires /proc filesystem)" >&2
  exit 1
fi

# Validate Splunk installation
if [ ! -d "$SPLUNK_HOME" ]; then
  echo "Error: SPLUNK_HOME directory not found: $SPLUNK_HOME" >&2
  exit 1
fi

if [ ! -f "$SPLUNK_HOME/var/run/splunk/splunkd.pid" ]; then
  echo "Error: Splunk PID file not found. Is Splunk running?" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"          # Create output directory if it doesn't exist

# Graceful shutdown handler
cleanup() {
  echo "" >&2
  echo "Shutting down kernel stack collection..." >&2
  exit 0
}

trap cleanup SIGTERM SIGINT

while true; do
    pid=$(head -1 "$SPLUNK_HOME/var/run/splunk/splunkd.pid")  # Read splunkd PID from file
    threads=$(grep Threads "/proc/$pid/status" 2>/dev/null | awk '{print $2}')  # Get number of threads

    # Check if number of threads is greater than 1000
    if [ -n "$threads" ] && [ "$threads" -gt 1000 ] 2>/dev/null; then
        timestamp=$(date +%Y-%m-%d_%H-%M-%S)  # Get current timestamp
        output_file="${OUTPUT_DIR}/kstacktrace_all.out"  # Output filename

        echo "Kernel Stack collection at ${timestamp}:" >> "$output_file"
        echo "" >> "$output_file"  # Add a blank line for separation

        # Loop through all running processes
        for i in $(ps auxww | awk '{print $2,$8}' | grep -v PID | awk '{print $1}'); do
            # Check if process ID is not empty
            if [ -n "$i" ]; then
                # Append process information and kernel stack to output file
                echo "Process Info (PID ${i}):" >> "$output_file"
                ps -fp "${i}" >> "$output_file" 2>/dev/null
                echo "Kernel Stack:" >> "$output_file"
                cat "/proc/${i}/stack" >> "$output_file" 2>/dev/null
                echo "" >> "$output_file"  # Add a blank line between each stack trace
            fi
        done
    fi
    sleep "$SAMPLE_PERIOD"
done