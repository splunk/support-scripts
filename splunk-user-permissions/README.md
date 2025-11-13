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
$SPLUNK_HOME/bin/python splk_user_perms.py -t <username>
```

### Python 3.6 Compatible Version

```bash
$SPLUNK_HOME/bin/python splk_user_perms_3.6.py -t <username>
```

### Options

- `-t, --target_user <username>` - **Required**. Username to check permissions for
- `-u, --url <url>` - Splunk REST API URL (default: https://localhost:8089)
- `-U, --username <user>` - Splunk admin username (will prompt if not provided)
- `-p, --password <pass>` - Splunk admin password (will prompt if not provided)
- `-b, --splunk_bin <path>` - Path to splunk binary (default: /opt/splunk/bin/splunk)
- `--verify-ssl` - Verify SSL certificates (default: disabled for self-signed certs)
- `-v, --verbose` - Verbosity level (repeat for more detail: -v, -vv, -vvv)

### Examples

```bash
# Check permissions for admin user (will prompt for credentials)
$SPLUNK_HOME/bin/python splk_user_perms.py -t admin

# Check user on remote Splunk instance with credentials
$SPLUNK_HOME/bin/python splk_user_perms.py -t analyst -u https://splunk-server:8089 -U admin -p password

# Verbose output with SSL verification
$SPLUNK_HOME/bin/python splk_user_perms.py -t analyst --verify-ssl -vv
```

## Output

The tool displays:

- User's assigned roles
- Capabilities per role (including inheritance)
- Index permissions per role
- Detected conflicts (capabilities or indexes both allowed and denied)

## Notes

- Tool connects via Splunk REST API and requires valid authentication
- SSL certificate verification disabled by default (use `--verify-ssl` to enable)
- **Security**: Avoid passing passwords via `-p` flag in production (visible in process list). Let script prompt for password instead.
- Use Python 3.6 version if running on older Splunk installations
- Script validates URL format to prevent basic injection issues
