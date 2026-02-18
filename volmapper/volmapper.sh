#!/bin/bash

# Initialize flags
SHOW_HOT=false
SHOW_COLD=false
SHOW_FROZEN=false
SHOW_ALL=true

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Map Splunk index paths to their underlying filesystem mount points and types."
    echo ""
    echo "OPTIONS:"
    echo "  -h, --hot          Show hot paths (homePath) only"
    echo "  -c, --cold         Show cold paths (coldPath) only"
    echo "  -f, --frozen       Show frozen paths (coldToFrozenDir) only"
    echo "  --help             Show this help message"
    echo ""
    echo "If no path type options are specified, all path types are shown."
    echo ""
    echo "Examples:"
    echo "  $0                 # Show all path types"
    echo "  $0 -h              # Show hot paths only"
    echo "  $0 -c -f           # Show cold and frozen paths only"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--hot)
            SHOW_HOT=true
            SHOW_ALL=false
            shift
            ;;
        -c|--cold)
            SHOW_COLD=true
            SHOW_ALL=false
            shift
            ;;
        -f|--frozen)
            SHOW_FROZEN=true
            SHOW_ALL=false
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# If no specific flags set, show all
if [[ "$SHOW_ALL" == true ]]; then
    SHOW_HOT=true
    SHOW_COLD=true
    SHOW_FROZEN=true
fi

# 1. Determine SPLUNK_HOME
S_HOME=${SPLUNK_HOME:-/opt/splunk}
LAUNCH_CONF="$S_HOME/etc/splunk-launch.conf"

# 2. Extract SPLUNK_DB from splunk-launch.conf
S_DB=$(grep "^SPLUNK_DB=" "$LAUNCH_CONF" | cut -d'=' -f2 | xargs)

# 3. Fallback to default if not defined and resolve $SPLUNK_HOME variable if present
S_DB=${S_DB:-$S_HOME/var/lib/splunk}
S_DB="${S_DB/\$SPLUNK_HOME/$S_HOME}"

echo "Using SPLUNK_DB: $S_DB"
echo "----------------------------------------------------------------------"
printf "%-20s %-10s %-50s %-20s %-10s\n" "STANZA" "PATH TYPE" "SPLUNK PATH" "MOUNT POINT" "FSTYPE"
echo "----------------------------------------------------------------------"

# Function to process path mappings
process_paths() {
    local path_type=$1
    local btool_pattern=$2
    local current_stanza=""

    $SPLUNK_HOME/bin/splunk btool indexes list 2>/dev/null | while IFS= read -r line; do
        # Check if this is a stanza header
        if [[ $line == \[*\] ]]; then
            current_stanza=$(echo "$line" | sed 's/\[//g; s/\]//g')
            continue
        fi

        # Check if this line matches our path pattern
        if [[ $line == *"$btool_pattern"* ]]; then
            # Extract the path value
            path=$(echo "$line" | cut -d'=' -f2 | xargs)

            # Filter out "0" and empty lines
            if [[ -z "$path" || "$path" == "0" ]]; then
                continue
            fi

            # Resolve $SPLUNK_DB to the actual filesystem path
            resolved_path="${path/\$SPLUNK_DB/$S_DB}"

            # Use findmnt to get TARGET (mount point) and FSTYPE (filesystem type)
            # -n (no headings), -o (output columns)
            mnt_info=$(findmnt -n -o TARGET,FSTYPE --target "$resolved_path" 2>/dev/null)

            # Print the results in a formatted table
            printf "%-20s %-10s %-50s %s\n" "$current_stanza" "$path_type" "$resolved_path" "$mnt_info"
        fi
    done
}

# 4. Run btool and process paths based on selected options
if [[ "$SHOW_HOT" == true ]]; then
    process_paths "HOT" "homePath ="
fi

if [[ "$SHOW_COLD" == true ]]; then
    process_paths "COLD" "coldPath ="
fi

if [[ "$SHOW_FROZEN" == true ]]; then
    process_paths "FROZEN" "coldToFrozenDir ="
fi
