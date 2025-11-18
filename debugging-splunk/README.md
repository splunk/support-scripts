# Debugging Splunk - Stack Collection Tool

Advanced pstack collection tool for the main splunkd process with multiple collection modes, Docker support, and sophisticated sampling options.

## Purpose

Collect detailed user-space stack traces from splunkd for debugging:

- Diagnose lock contention, deadlocks, and thread exhaustion issues
- Capture consistent snapshots with optional process freezing
- Support production environments with minimal disruption
- Collect data from Docker containers
- Provide comprehensive diagnostic data for Splunk Support

## Requirements

- **Linux only**
- **elfutils package** (provides `eu-stack` command)
  - Install: `yum install elfutils` or `apt install elfutils`
  - Alternatively: uses `pstack` or `gdb` as fallback (set `FORCE_PSTACK=1` or `FORCE_GDB=1`)
- **Root privileges or splunk user** (to read process memory)
- Splunk Enterprise installation (default: `/opt/splunk`)
- For REST API mode: Splunk user with `request_pstacks` capability

## Usage

### Basic Usage

```bash
# Make executable
chmod +x collect-stacks.sh

# Run with defaults (1000 samples at 0.5s intervals)
./collect-stacks.sh

# Batch mode (no prompts)
./collect-stacks.sh --batch

# Custom sample count and interval
./collect-stacks.sh --samples=500 --interval=1.0

# Specify custom PID
./collect-stacks.sh --pid=12345

# Custom output directory
./collect-stacks.sh --outdir=/var/tmp/diagnostics
```

### Advanced Options

```bash
# Continuous mode (keeps latest N samples, runs indefinitely)
./collect-stacks.sh --continuous --samples=100

# Freeze process during collection (for consistent snapshots - DISRUPTIVE)
./collect-stacks.sh --freeze

# Collect from Docker container
./collect-stacks.sh --docker=<container-id> --pid=<pid-inside-container>

# Use Splunk REST API instead of eu-stack
./collect-stacks.sh --rest

# Quiet mode (minimal output)
./collect-stacks.sh --quiet --batch
```

### Full Options List

```
-b, --batch               Non-interactive mode
-c, --continuous          Collect data continuously, keeping only latest <samples>
-d, --docker=CONTAINER_ID Collect from inside docker container
-f, --freeze              Freeze process during collection (DISRUPTIVE)
-h, --help                Print help message
-i, --interval=INTERVAL   Interval between samples (seconds, default: 0.5)
-o, --outdir=PATH         Output directory (default: /tmp/splunk)
-p, --pid=PID             Process ID to monitor
-q, --quiet               Silent mode
-r, --rest                Use Splunk REST API endpoint
-s, --samples=COUNT       Number of samples (default: 1000)
```

## Output

Creates timestamped directory in `/tmp/splunk/stacks-<pid>-<hostname>-<timestamp>/`:

- `stack-<timestamp>.out` - Application stack traces (from eu-stack or pstack)
- `stack-<timestamp>.err` - stderr output (warnings, harmless DWARF messages)
- `proc-stack-<timestamp>.out` - Kernel stack traces from `/proc/*/stack`
- `proc-status-<timestamp>.out` - Thread status from `/proc/*/status`
- `proc-maps.out` - Memory mappings

Automatically archives to compressed tarball: `/tmp/splunk/stacks-*.tar.xz`

### Example Output Structure

```
/tmp/splunk/stacks-12345-indexer01-2024-01-15T14h23m45s.tar.xz
  └── stacks-12345-indexer01-2024-01-15T14h23m45s/
      ├── proc-maps.out
      ├── stack-2024-01-15T14h23m45s123456789ns+0000.out
      ├── stack-2024-01-15T14h23m45s123456789ns+0000.err
      ├── proc-stack-2024-01-15T14h23m45s123456789ns+0000.out
      ├── proc-status-2024-01-15T14h23m45s123456789ns+0000.out
      └── ... (1000 samples total)
```

## Notes

- **Default 1000 samples at 0.5s = 8+ minutes of collection time**
- Script validates that collected stacks contain thread information before proceeding
- Normal to see `.err` files with benign DWARF warnings - filtered automatically
- `--freeze` option stops process during collection (use ONLY when absolutely necessary)
- Continuous mode overwrites oldest samples - useful for long-running monitoring
- REST API mode requires Splunk credentials with `request_pstacks` capability
- Docker mode requires `nsenter` and proper container ID
- Archives automatically include all collected samples in compressed tarball
- Original sample files removed after successful archival
- For Splunk Support cases: upload archive + generate diag separately
