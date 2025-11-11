# Splunk User Permissions Checker

Checks and analyzes Splunk user permissions by querying the Splunk REST API. Identifies role assignments, capabilities, index access, and detects permission conflicts across roles.

## Purpose

Helps administrators audit user permissions in Splunk environments by:
- Displaying all roles assigned to a user
- Listing capabilities (enabled and disabled)
- Showing index permissions (allowed and restricted)
- Detecting conflicts where permissions are both granted and denied

## Requirements

- Splunk Enterprise installation
- Python 3.6+ (for `splk_user_perms.py`)
- Python 3.6 specifically (for `splk_user_perms_3.6.py`)
- Access to Splunk REST API
- Valid Splunk credentials

## Usage

### Standard Version

```bash
$SPLUNK_HOME/bin/python splk_user_perms.py --user <username>
```

### Python 3.6 Compatible Version

```bash
$SPLUNK_HOME/bin/python splk_user_perms_3.6.py --user <username>
```

### Options

- `--user <username>` - Required. Username to check permissions for
- `--host <url>` - Splunk instance URL (default: https://localhost:8089)
- `--verbose` or `-v` - Enable verbose output for debugging

### Example

```bash
# Check permissions for admin user
$SPLUNK_HOME/bin/python splk_user_perms.py --user admin

# Check user on remote Splunk instance
$SPLUNK_HOME/bin/python splk_user_perms.py --user analyst --host https://splunk-server:8089
```

## Output

The tool displays:
- User's assigned roles
- Capabilities per role (including inheritance)
- Index permissions per role
- Detected conflicts (capabilities or indexes both allowed and denied)

## Notes

- Tool connects via Splunk REST API and requires valid authentication
- Disables SSL warnings for self-signed certificates
- Use Python 3.6 version if running on older Splunk installations
