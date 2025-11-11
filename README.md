# Splunk Support Scripts

A curated collection of diagnostic and administrative tools for Splunk environments, maintained by Splunk Support for customer use. These scripts help troubleshoot common issues, validate configurations, and perform routine maintenance tasks.

## Available Tools

### Configuration & Security

#### KV Store Certificate Verifier

Validates KV Store certificate configurations before upgrading from MongoDB 4/4.2 to 7. Checks SSL settings, certificate chains, and compatibility requirements.

```bash
cd kvcertverify
$SPLUNK_HOME/bin/python kv_cert_verifier.py $SPLUNK_HOME
```

[Full documentation](kvcertverify/README.md)

#### Splunk Config Checker

Generic configuration validator using JSON-based rules. Checks settings across multiple conf files with custom severity levels and detailed reporting.

```bash
cd splunk_config_checker
$SPLUNK_HOME/bin/python splunk_config_checker.py $SPLUNK_HOME
```

[Full documentation](splunk_config_checker/README.md)

### User & Permission Management

#### Splunk User Permissions Checker

Audits user permissions by querying REST API. Shows role assignments, capabilities, index access, and detects permission conflicts.

```bash
cd splunk-user-permissions
$SPLUNK_HOME/bin/python splk_user_perms.py --user <username>
```

[Full documentation](splunk-user-permissions/README.md)

### Input & Data Management

#### Find Duplicate Inputs

Scans configuration files to identify duplicate or overlapping monitor inputs that could cause data duplication.

```bash
cd find-duplicate-inputs
./find_duplicate_inputs.sh
```

[Full documentation](find-duplicate-inputs/README.md)

#### Lookup Generator

Creates large test CSV lookup files with randomized data for performance testing and development.

```bash
cd lookup-generator
./lookup_gen.sh
```

[Full documentation](lookup-generator/README.md)

### Cluster & Network Diagnostics

#### Test Peers

Tests TCP connectivity to all distributed search peers on port 8089. Auto-discovers peers from configuration.

```bash
cd test-peers
./testpeers.sh
```

[Full documentation](test-peers/README.md)

### Testing & Validation

#### New Log Event (Windows)

PowerShell script to generate custom-sized Windows Event Log entries for testing ingestion pipelines.

```powershell
cd new-log-event
.\New-LogEvent.ps1 -Size 8000 -Path Application
```

[Full documentation](new-log-event/README.md)

## General Requirements

Most scripts require one or more of:
- Splunk Enterprise installation
- Splunk's Python interpreter (`$SPLUNK_HOME/bin/python`)
- Bash shell (Linux/macOS)
- PowerShell 5.1+ (Windows-specific tools)

Refer to individual tool documentation for specific requirements.

## Getting Help

Each tool has its own README with detailed usage instructions, parameters, and troubleshooting guidance. Navigate to the tool's directory and review the README.md file.

## Authors

- Tyler Ezell - Initial work and maintenance
