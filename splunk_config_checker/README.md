# Splunk Configuration Checker

A generic configuration checker for Splunk configurations that verifies settings across different conf files using rules defined in JSON.

## Overview

The Splunk Configuration Checker is a flexible tool that allows you to:

- Define configuration checks in a JSON file
- Check settings across multiple Splunk configuration files
- Set different severity levels for checks (INFO, WARN, ERROR)
- Provide custom messages for failed checks
- Handle inheritance in Splunk configurations (e.g., tcpout stanza defaults)

## Usage

### Basic Usage

1. Define your configuration rules in `config_rules.json`:

```json
{
    "rules": [
        {
            "filename": "outputs",
            "stanza": "tcpout",
            "setting": "compressed",
            "expected_value": true,
            "level": "WARN",
            "message": "Data compression should be enabled for tcpout"
        }
    ]
}
```

2. Use the checker in your code:

```python
from splunk_config_checker import SplunkConfigChecker
from pathlib import Path

splunk_home = Path("/opt/splunk")
rules_file = Path("config_rules.json")

checker = SplunkConfigChecker(splunk_home, rules_file)
results = checker.check_configurations()
checker.print_results(results)
```

### Rule Format

Each rule in the JSON file must include:

- `filename`: The Splunk configuration file name without .conf extension
- `stanza`: The configuration stanza name
- `setting`: The configuration setting key
- `expected_value`: The expected value for the setting
- `level` (optional): Severity level - "INFO", "WARN", or "ERROR" (default: "WARN")
- `message` (optional): Custom message to display when check fails

### Example Rules

```json
{
    "rules": [
        {
            "filename": "outputs",
            "stanza": "tcpout",
            "setting": "compressed",
            "expected_value": true,
            "level": "WARN",
            "message": "Data compression should be enabled for tcpout"
        },
        {
            "filename": "server",
            "stanza": "sslConfig",
            "setting": "allowSslCompression",
            "expected_value": true,
            "level": "WARN"
        }
    ]
}
```

## Special Handling

### Stanza Inheritance

The checker handles special cases like tcpout stanza inheritance in outputs.conf:

- If a setting is not found in a `tcpout::` stanza, it will check the parent `tcpout` stanza
- This follows Splunk's configuration inheritance rules

### Value Types

The checker supports different value types:

- Strings: `"expected_value": "value"`
- Booleans: `"expected_value": true`
- Numbers: `"expected_value": 8089`

Values are compared case-insensitively for boolean values ("true"/"false").

## Adding New Rules

To add new configuration checks:

1. Open `config_rules.json`
2. Add a new rule object to the `rules` array
3. Include all required fields (filename, stanza, setting, expected_value)
4. Add optional fields (level, message) as needed
5. Save the file

The checker will automatically pick up and verify the new rules.