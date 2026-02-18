# Log Redactor

Redact sensitive information from log files, replacing PII with consistent random identifiers for trackability.

## Purpose

When sharing Splunk diag files or log excerpts with support engineers or in meeting chats, sensitive data must be removed. This tool automatically redacts:

- IP addresses (IPv4 and IPv6)
- Hostnames (FQDNs and common patterns)
- GUIDs/UUIDs
- Email addresses
- MAC addresses (colon, hyphen, and Cisco dot notation)
- Data-host fields (multiple formats including `=`, `:`, JSON, XML, camelCase, underscore variants)

Each unique value gets a consistent random identifier — the same IP appearing on multiple lines will always map to the same `[REDACTED-IP-XXXXXX]` tag.

## Requirements

- Python 3.6+
- No external dependencies (stdlib only)

## Usage

```bash
python redactme.py <input_file> <output_file> [OPTIONS]
```

### Options

- `--demo` - Run demonstration with sample data
- `--no-header` - Omit metadata header from output file
- `--mapping-report` - Append redaction mapping report to output file
- `--json-export FILE` - Export mappings to JSON
- `--csv-export FILE` - Export mappings to CSV
- `--seed INT` - Set random seed for reproducible redaction IDs
- `--quiet` - Suppress console output

### Examples

```bash
# Basic redaction
python redactme.py /path/to/splunk.log redacted_output.log

# With mapping report appended to output
python redactme.py diag.log redacted.log --mapping-report

# Export mappings for reference
python redactme.py diag.log redacted.log --json-export mappings.json

# Reproducible IDs across runs
python redactme.py diag.log redacted.log --seed 42

# Run built-in demo
python redactme.py --demo
```

## Example Output

Original:
```
2024-01-15 10:23:45 INFO  Connection from 192.168.1.100 to server01.company.com
2024-01-15 10:23:47 WARN  Failed login from 10.0.0.55 for admin@internal.corp.net
2024-01-15 10:26:00 INFO  data-host=production-server-01 received request
```

Redacted:
```
2024-01-15 10:23:45 INFO  Connection from [REDACTED-IP-482910] to [REDACTED-HOST-738291]
2024-01-15 10:23:47 WARN  Failed login from [REDACTED-IP-193847] for [REDACTED-EMAIL-572910]
2024-01-15 10:26:00 INFO  data-host=[REDACTED-DATAHOST-849201] received request
```

## Notes

- Review redacted output before sharing — regex-based redaction may not catch all sensitive patterns
- The `--mapping-report` option appends a summary showing original-to-redacted mappings (do not share this)
- Data-host field detection covers `=`, `:`, quoted, JSON, XML, camelCase, PascalCase, and underscore variants
- Large files are processed line-by-line to keep memory usage low
- Report any missed redaction patterns to jnenadal@cisco.com
