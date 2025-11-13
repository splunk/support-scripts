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

## How It Works

The script normalizes paths to detect potential duplicates:

1. Converts Windows backslashes to forward slashes
2. Removes file pattern suffixes (e.g., `*.log`, `file.*`)
3. Compares normalized paths (case-sensitive)

This groups paths like `/var/log/*.log` and `/var/log/app.log` as potential duplicates since they may overlap.

## Output

Prints all monitor stanzas that have matching normalized paths. Each line shows:

- Configuration file path
- The monitor stanza found

### Example Output

```
./etc/apps/app1/local/inputs.conf:[monitor:///var/log]
./etc/apps/app2/default/inputs.conf:[monitor:///var/log/*.log]
```

No output means no potential duplicates detected.

## Notes

- Path matching is **case-sensitive** (as Unix filesystems are)
- Groups directory monitors with file pattern monitors that could overlap
- Useful for troubleshooting duplicate data ingestion or config audits
