# Splunk Support Scripts

A curated collection of diagnostic and administrative tools for Splunk environments, maintained by Splunk Support for customer use. These scripts help troubleshoot common issues, validate configurations, and perform routine maintenance tasks.

## Available Tools

### Configuration & Security

**[KV Store Certificate Verifier](kvcertverify/README.md)** - Verify KV Store certificates before MongoDB upgrade

- **Problem**: Need to verify KV Store certificates before upgrading MongoDB from 4/4.2 to 7
- **Solution**: Validates SSL settings, certificate chains, and compatibility requirements

**[Splunk Config Checker](splunk_config_checker/README.md)** - Generic configuration validator

- **Problem**: Need to validate Splunk configurations across multiple conf files
- **Solution**: JSON-based rule validator with custom severity levels and detailed reporting

### User & Permission Management

**[Splunk User Permissions Checker](splunk-user-permissions/README.md)** - Audit user permissions and conflicts

- **Problem**: Need to audit user permissions and identify conflicts
- **Solution**: Queries REST API to show role assignments, capabilities, index access, and permission conflicts

### Input & Data Management

**[Find Duplicate Inputs](find-duplicate-inputs/README.md)** - Detect overlapping monitor inputs

- **Problem**: Duplicate data ingestion from overlapping monitor inputs
- **Solution**: Scans inputs.conf files to identify duplicate or overlapping monitor paths

**[Lookup Generator](lookup-generator/README.md)** - Generate large test lookup files

- **Problem**: Need large test lookup files for performance testing
- **Solution**: Generates CSV files with randomized data up to specified size (default 14MB)

### Cluster & Network Diagnostics

**[Test Peers](test-peers/README.md)** - Verify distributed search peer connectivity

- **Problem**: Need to verify distributed search peer connectivity
- **Solution**: Auto-discovers peers and tests TCP connectivity on port 8089

### Performance & Diagnostics

**[Kernel Stacks Splunk Threads](kernel-stacks-splunk-threads/README.md)** - Monitor Splunk threads and collect kernel stacks (Linux only)

- **Problem**: Need to diagnose Splunk thread exhaustion and capture system state during incidents
- **Solution**: Monitors splunkd thread count and automatically collects kernel stack traces when threshold exceeded

### Testing & Validation

**[New Log Event](new-log-event/README.md)** - Generate Windows event log entries (Windows only)

- **Problem**: Need to test Windows event log ingestion with specific event sizes
- **Solution**: PowerShell script to generate custom-sized event log entries

## General Requirements

Most scripts require one or more of:

- Splunk Enterprise installation
- Splunk's Python interpreter (`$SPLUNK_HOME/bin/python`)
- Bash shell (Linux/macOS)
- PowerShell 3.0+ (Windows-specific tools)

Refer to individual tool documentation for specific requirements.

## Getting Help

Each tool has its own README with detailed usage instructions, parameters, and troubleshooting guidance. Navigate to the tool's directory and review the README.md file.

## Contributing

Team members can contribute new scripts by following these guidelines:

### Adding a New Script

1. **Create a dedicated folder** using kebab-case naming (e.g., `my-new-tool/`)
2. **Include the script(s)** with appropriate execute permissions for shell scripts
3. **Create a README.md** with the following sections:
   - Purpose (what problem it solves)
   - Requirements
   - Usage (with clear examples)
   - Parameters/options
   - Example output (if helpful)
   - Notes (compatibility, limitations, etc.)
4. **Update top-level README.md** to add your tool to the appropriate category

### README Template

```markdown
# Tool Name

Brief description of what the tool does.

## Purpose

Explain the problem this tool solves and use cases.

## Requirements

- List dependencies
- Note OS compatibility
- Specify version requirements

## Usage

\`\`\`bash
./script.sh [options]
\`\`\`

### Options

- `-o, --option` - Description

### Examples

\`\`\`bash

# Example 1

./script.sh --example

# Example 2

./script.sh --another-example
\`\`\`

## Notes

- Important compatibility notes
- Known limitations
- Security considerations (if applicable)
```

### Code Quality Expectations

- Scripts should include error handling
- Shell scripts must have shebang lines (`#!/bin/bash`)
- Cross-platform compatibility when possible (test on Linux/macOS)
- Clear comments for complex logic
- Security best practices (avoid hardcoded credentials, validate inputs)
- Scripts cannot change customer environment apart from creating logging files
- When using python, if at all possible, use the python packaged with Splunk for consistencies sake

### Submitting Scripts

Send scripts to the repository maintainer for review. Include:

- Script file(s)
- README documentation
- Brief description of testing performed

## Authors

- Tyler Ezell - Initial scripts and maintenance.
- Rob Hilgefort - Repository setup, review, and stewardship.
