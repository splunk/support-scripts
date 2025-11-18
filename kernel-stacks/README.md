# Kernel Stacks - D-State Process Monitor

Continuously monitors and captures kernel stack traces specifically for processes in uninterruptible sleep ("D" state), which indicates processes stuck in kernel operations waiting for I/O or resources.

## Purpose

Diagnose processes stuck in uninterruptible sleep state to:

- Identify I/O bottlenecks causing process hangs
- Debug kernel-level blocking issues (disk I/O, NFS hangs, device locks)
- Capture diagnostic data for processes that cannot be interrupted or debugged normally
- Correlate D-state processes with system performance degradation
- Provide kernel-level visibility for hung process investigations

## Requirements

- **Linux only** (uses `/proc` filesystem)
- **Root privileges required** (reads `/proc/*/stack`)
- Bash shell
- Kernel stack traces enabled (enabled by default in most distributions)

## Usage

```bash
# Make executable
chmod +x kstacks.sh

# Create output directory
sudo mkdir -p /tmp/kstacks

# Run interactively (must be root)
sudo ./kstacks.sh

# Run in background, persisting after logout
sudo nohup ./kstacks.sh &

# Verify running
ps -ef | grep kstacks | grep -v grep

# Stop collection
sudo pkill -f kstacks.sh
```

### Configuration

Edit script variables to customize:

- `OUTPUT_DIR` - Output directory (default: `/tmp/kstacks`)
- `SAMPLE_PERIOD` - Seconds between checks (default: 2)

## Output

Creates `/tmp/kstacks/kstacktrace.out` containing:

- Process information for each D-state process detected
- Kernel stack trace from `/proc/PID/stack`
- Continuous append mode - all samples in single file

### Example Output

```
UID        PID  PPID  C STIME TTY          TIME CMD
root      1234  1000  0 14:20 ?        00:00:00 dd if=/dev/zero of=/mnt/nfs/test bs=1M

[<0>] nfs_file_fsync+0x3e/0x80 [nfs]
[<0>] vfs_fsync_range+0x4b/0xb0
[<0>] do_fsync+0x38/0x60
[<0>] __x64_sys_fsync+0x10/0x20
[<0>] do_syscall_64+0x5b/0x1b0
```

## Notes

- **Only monitors D-state processes** (uninterruptible sleep waiting for I/O/resources)
- D-state processes cannot be killed or interrupted - typically waiting on disk I/O, NFS, or device locks
- No output if no D-state processes exist - this is normal behavior
- Root access required to read `/proc/*/stack` files
- Output file grows unbounded - monitor disk space in `/tmp`
- Runs continuously until manually stopped - no automatic exit
- Log file is appended to, not rotated - manual cleanup required
- Samples every 2 seconds by default - can be adjusted via `SAMPLE_PERIOD`
- Script now includes automatic output directory creation and root privilege check
