# Kernel Stacks Splunk Threads

Monitors Splunk thread count and collects kernel stack traces from all processes when thread count exceeds threshold. Useful for diagnosing performance issues and thread exhaustion in Splunk deployments.

## Purpose

Automatically capture system-wide kernel stack traces when Splunk exhibits thread exhaustion to:

- Diagnose what's consuming threads during high-load incidents
- Correlate Splunk thread spikes with system process behavior
- Capture diagnostic data automatically without manual intervention
- Provide kernel-level visibility for support investigations

## Requirements

- **Linux only** (uses `/proc` filesystem)
- **Root privileges required** (reads `/proc/*/stack`)
- Bash shell
- Splunk Enterprise installation at `/opt/splunk` (or edit `SPLUNK_HOME` variable)
- Kernel stack traces enabled (most distributions enable by default)

## Usage

```bash
# Make executable
chmod +x kstack_threads.sh

# Run interactively (must be root)
sudo ./kstack_threads.sh

# Run in background, persisting after logout
sudo nohup ./kstack_threads.sh &

# Verify running
ps -ef | grep kstack_threads | grep -v grep

# Stop collection
sudo pkill -f kstack_threads.sh
```

### Configuration

Edit script variables to customize:

- `OUTPUT_DIR` - Output directory (default: `/tmp/kstacks`)
- `SPLUNK_HOME` - Splunk installation path (default: `/opt/splunk`)
- `SAMPLE_PERIOD` - Seconds between checks (default: 1)
- Thread threshold hardcoded to 1000 (line 14)

## Output

Creates `/tmp/kstacks/kstacktrace_all.out` containing:

- Timestamp of each collection event
- For each running process:
  - Process info (PID, user, command)
  - Kernel stack trace from `/proc/PID/stack`

### Example Output

```
Kernel Stack collection at 2024-01-15_14-23-45:

Process Info (PID 12345):
UID        PID  PPID  C STIME TTY          TIME CMD
splunk   12345     1  5 14:20 ?        00:00:12 splunkd

Kernel Stack:
[<0>] poll_schedule_timeout+0x4e/0x80
[<0>] do_sys_poll+0x3d4/0x570
[<0>] __x64_sys_poll+0x18a/0x1f0
```

## Notes

- **Collects stacks from ALL system processes**, not just Splunk - may expose sensitive process information
- Runs continuously until manually stopped - no automatic exit
- Output file grows unbounded - monitor disk space in `/tmp`
- Only triggers collection when splunkd threads exceed 1000
- Samples every second by default - adjust `SAMPLE_PERIOD` for less frequent checks
- Root access required to read most `/proc/*/stack` files
- Log file is appended to, not rotated - manual cleanup required
