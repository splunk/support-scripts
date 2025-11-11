# Splunk Support Scripts

A curated collection of diagnostic and administrative tools for Splunk environments, maintained by Splunk Support for customer use. These scripts help troubleshoot common issues, validate configurations, and perform routine maintenance tasks.

## Available Tools

### Configuration & Security

**[KV Store Certificate Verifier](kvcertverify/README.md)**
Problem: Need to verify KV Store certificates before upgrading MongoDB from 4/4.2 to 7
Solution: Validates SSL settings, certificate chains, and compatibility requirements

**[Splunk Config Checker](splunk_config_checker/README.md)**
Problem: Need to validate Splunk configurations across multiple conf files
Solution: Generic validator using JSON-based rules with custom severity levels and detailed reporting

### User & Permission Management

**[Splunk User Permissions Checker](splunk-user-permissions/README.md)**
Problem: Need to audit user permissions and identify conflicts
Solution: Queries REST API to show role assignments, capabilities, index access, and permission conflicts

### Input & Data Management

**[Find Duplicate Inputs](find-duplicate-inputs/README.md)**
Problem: Duplicate data ingestion from overlapping monitor inputs
Solution: Scans inputs.conf files to identify duplicate or overlapping monitor paths

**[Lookup Generator](lookup-generator/README.md)**
Problem: Need large test lookup files for performance testing
Solution: Generates CSV files with randomized data up to specified size (default 14MB)

### Cluster & Network Diagnostics

**[Test Peers](test-peers/README.md)**
Problem: Need to verify distributed search peer connectivity
Solution: Auto-discovers peers and tests TCP connectivity on port 8089

### Testing & Validation

**[New Log Event](new-log-event/README.md)** (Windows)
Problem: Need to test Windows event log ingestion with specific event sizes
Solution: PowerShell script to generate custom-sized event log entries

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
- Rob Hilgefort - Repository setup, review, and stewardship
