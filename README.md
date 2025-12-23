# Splunk Support Scripts

A curated collection of diagnostic and administrative tools for Splunk environments, maintained by Splunk Support for customer use. These scripts help troubleshoot common issues, validate configurations, and perform routine maintenance tasks.

## Table of Contents

- [Splunk Support Scripts](#splunk-support-scripts)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Available Tools](#available-tools)
    - [Configuration \& Security](#configuration--security)
    - [User \& Permission Management](#user--permission-management)
    - [Input \& Data Management](#input--data-management)
    - [Cluster \& Network Diagnostics](#cluster--network-diagnostics)
    - [Performance \& Diagnostics](#performance--diagnostics)
    - [Testing \& Validation](#testing--validation)
  - [General Requirements](#general-requirements)
  - [Contributing](#contributing)
    - [Adding a New Script](#adding-a-new-script)
    - [README Template](#readme-template)
    - [Code Quality Expectations](#code-quality-expectations)
    - [Submitting Scripts](#submitting-scripts)
  - [Authors](#authors)
  - [Changelog](#changelog)
    - [v1.2.0 - 2025-11-21](#v120---2025-11-21)
    - [v1.1.0 - 2025-11-18](#v110---2025-11-18)
    - [v1.0.0 - Initial Release](#v100---initial-release)

## Getting Started

Clone and navigate to the repository:

```bash
git clone https://github.com/splunk/support-scripts.git
cd support-scripts
```

**Bash script example:**

```bash
cd test-peers
./testpeers.sh
```

**Python script example:**

```bash
cd kvcertverify
$SPLUNK_HOME/bin/python kvcertverify.py --help
```

Requires Splunk Enterprise access. See individual tool READMEs for detailed usage.

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

**Note:** For advanced stack collection tools, see [Splunk UF Diagnosability Tools](https://github.com/splunk/uf-diagnosability)

**[Kernel Stacks - D-State Monitor](kernel-stacks/README.md)** - Monitor D-state processes and collect kernel stacks (Linux only)

- **Problem**: Need to diagnose processes stuck in uninterruptible sleep (D-state) waiting for I/O or resources
- **Solution**: Continuously monitors and captures kernel stacks specifically for D-state processes to identify I/O bottlenecks

**[Kernel Stacks Splunk Threads](kernel-stacks-splunk-threads/README.md)** - Monitor Splunk threads and collect kernel stacks (Linux only)

- **Problem**: Need to diagnose Splunk thread exhaustion and capture system state during incidents
- **Solution**: Monitors splunkd thread count and automatically collects kernel stack traces when threshold exceeded

**[Splunkd Pstacks Threads Monitor](splunkd-pstacks-threads/README.md)** - Monitor main splunkd threads and collect pstacks (Linux only)

- **Problem**: Need to automatically capture user-space stack traces when splunkd thread count exceeds 500
- **Solution**: Monitors main splunkd process and collects pstack dumps to diagnose lock contention and thread exhaustion

**[Process-Runner Pstacks Threads Monitor](process-runner-pstacks-threads/README.md)** - Monitor process-runner threads and collect pstacks (Linux only)

- **Problem**: Need to diagnose thread issues specific to Splunk process-runner (scripted inputs, custom commands)
- **Solution**: Monitors process-runner thread count and collects pstack dumps to identify issues with external process execution

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
- Scripts cannot change customer environment apart from creating logging files. [See AI usage guidelines](https://cisco.sharepoint.com/sites/AIML/SitePages/ApprovedGAITools.aspx?csf=1&web=1&e=3jDh3H)
- When using python, if at all possible, use the python packaged with Splunk for consistencies sake

### Submitting Scripts

Send scripts to the repository maintainer for review. Include:

- Script file(s)
- README documentation
- Brief description of testing performed

## Authors

- Tyler Ezell (tezell@splunk.com) - Initial scripts and maintenance
- Robert Phillips (rphillips@splunk.com) - Performance diagnostics and stack collection tools
- Niclas Andersson (nandersson@splunk.com)
- Rob Hilgefort (rhilgefort@splunk.com) - Repository setup, review, and stewardship

## Changelog

### v1.3.0 - 2025-12-22

**Updated:**

- `README.md` - Added AI usage guidelines link to contributing section
- `splunk_config_checker` - Added rule-based validation system with configurable rules
- `new-log-event/README.md` - Added disclaimer for test data generation and Security log limitation note
- `lookup-generator/README.md` - Added disclaimer for test data generation

**Removed:**

- `debugging-splunk` - Removed in favor of upstream repo at https://github.com/splunk/uf-diagnosability

### v1.2.0 - 2025-11-21

**Updated:**

- `README.md` - Added table of contents, getting started section, and changelog

### v1.1.0 - 2025-11-18

**Added:**

- `debugging-splunk` - Advanced pstack collection tool for main splunkd with multiple collection modes
- `kernel-stacks` - D-state process monitor for diagnosing uninterruptible sleep issues
- `splunkd-pstacks-threads` - Automatic pstack collection when main splunkd thread count exceeds 500
- `process-runner-pstacks-threads` - Automatic pstack collection when process-runner thread count exceeds 500

### v1.0.0 - Initial Release

**Included:**

- `kvcertverify` - KV Store certificate verifier for MongoDB upgrades
- `splunk_config_checker` - Generic configuration validator
- `splunk-user-permissions` - User permissions and conflicts auditor
- `find-duplicate-inputs` - Duplicate monitor input detector
- `lookup-generator` - Large test lookup file generator
- `test-peers` - Distributed search peer connectivity tester
- `kernel-stacks-splunk-threads` - Kernel stack collector triggered by Splunk thread threshold
- `new-log-event` - Windows event log entry generator
