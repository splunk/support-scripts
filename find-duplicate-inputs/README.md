# Find Duplicate Inputs

Identifies duplicate monitor input configurations across Splunk configuration files. Helps prevent data duplication issues by detecting multiple monitor stanzas pointing to the same file paths.

## Purpose

When multiple `inputs.conf` files contain overlapping monitor paths, Splunk may index the same data multiple times. This tool scans all `inputs.conf` files and identifies duplicate or overlapping monitor configurations.

## Requirements

- Bash shell
- Access to Splunk configuration directories
- Standard Unix tools (find, grep, awk)

## Usage

```bash
cd /path/to/splunk
./find_duplicate_inputs.sh
```

The script searches from the current directory, so run it from your Splunk installation root or the specific directory tree you want to check.

### Example

```bash
# Check for duplicates in entire Splunk installation
cd $SPLUNK_HOME
/path/to/find_duplicate_inputs.sh

# Check specific app directory
cd $SPLUNK_HOME/etc/apps/my_app
/path/to/find_duplicate_inputs.sh
```

## Output

The script prints all duplicate monitor stanza configurations found. If duplicates exist, it displays:
- File path containing the duplicate
- The monitor path that's duplicated
- All locations where the duplicate appears

No output means no duplicates were detected.

## Notes

- Script normalizes paths (handles case differences and wildcards)
- Checks for overlapping directory monitors that could cause duplication
- Useful for troubleshooting duplicate data issues or config audits
