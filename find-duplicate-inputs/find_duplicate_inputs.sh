#!/bin/bash

# Find all inputs.conf files and search for duplicate monitor stanzas
# Normalizes paths to detect overlapping configurations

find . -name inputs.conf -exec grep -H 'monitor' {} \; | awk -F'[][]' '
{
    # Extract the path after "monitor://"
    raw_path = substr($2, index($2, "monitor://") + length("monitor://"))

    # Normalize the path for comparison
    normalized_path = raw_path

    # Convert Windows backslashes to forward slashes
    gsub(/\\/, "/", normalized_path)

    # Remove file pattern suffix (e.g., *.log, file.*)
    # This groups /var/log/*.log with /var/log/app.log as potential duplicates
    sub(/\/[^/]*[\\.\\*][^/]*$/, "", normalized_path)

    # Store the original line keyed by normalized path
    lines[normalized_path][++count[normalized_path]] = $0
}
END {
    # Print all instances where a normalized path appears more than once
    for (path in count) {
        if (count[path] > 1) {
            for (i = 1; i <= count[path]; i++) {
                print lines[path][i]
            }
        }
    }
}
'
