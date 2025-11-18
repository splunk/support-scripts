# Process-Runner Pstacks Threads Monitor

Monitors Splunk process-runner thread count and automatically collects pstack dumps when thread count exceeds 500, indicating potential issues with scripted inputs, custom commands, or external process execution.

## Purpose

Automatically capture user-space stack traces from process-runner during thread exhaustion to:

- Diagnose thread issues specific to process-runner (scripted inputs, custom commands)
- Detect lock contention and deadlocks in external process execution
- Identify issues with scripted input execution or custom search commands
- Capture diagnostic data automatically when threshold exceeded
- Distinguish process-runner issues from main splunkd issues

## Requirements

- **Linux only** (uses `/proc` filesystem)
- **pstack or gdb** installed
  - RHEL/CentOS: `yum install gdb`
  - Ubuntu/Debian: `apt install gdb`
- Splunk Enterprise installation at `/opt/splunk` (or edit `SPLUNK_HOME` variable)
- Access to read process memory (run as splunk user or root)

## Usage

```bash
# Make executable
chmod +x pstack_threads.sh

# Run interactively
./pstack_threads.sh

# Run in background, persisting after logout
nohup ./pstack_threads.sh &

# Verify running
ps -ef | grep pstack | grep -v grep

# Stop collection
kill $(ps -ef | grep pstack_threads.sh | grep -v grep | awk '{print $2}')
```

### Configuration

Edit script variables to customize:

- `OUTPUT_DIR` - Output directory (default: `/tmp`)
- `SPLUNK_HOME` - Splunk installation path (default: `/opt/splunk`)
- `SAMPLE_PERIOD` - Seconds between checks (default: 1)
- Thread threshold hardcoded to 500 (line 51)

## Output

Creates timestamped files in `/tmp`:

```
pstack_process-runner-<pid>-<threads>-<unix_timestamp>.out
```

Example: `pstack_process-runner-12346-627-1705335825.out`

### Example Output

```
Thread 1 (LWP 12346):
#0  0x00007f8a1234abcd in waitpid () from /lib64/libc.so.6
#1  0x000000000123456 in ProcessRunner::executeScript()
#2  0x000000000234567 in ScriptedInputRunner::run()
#3  0x00007f8a1345bcde in start_thread () from /lib64/libpthread.so.0

Thread 2 (LWP 12347):
...
```

## Process-Runner Background

The **process-runner** is a separate Splunk process (second PID in `splunkd.pid`) responsible for:

- Executing scripted inputs (`bin/` scripts)
- Running custom search commands
- Managing external process execution
- Isolating external processes from main splunkd

Thread exhaustion in process-runner often indicates:
- Too many concurrent scripted inputs
- Hung or slow-running scripts
- Resource contention in custom commands
- Issues with external process management

## Notes

- **Targets process-runner, not main splunkd** - second PID in splunkd.pid file
- **Threshold of 500 threads** - indicates potential scripted input or custom command issues
- Normal process-runner: ~50-100 threads depending on scripted input count
- Samples every 1 second - minimal overhead when below threshold
- Only collects pstack when threshold exceeded - no output otherwise
- Script includes robust error handling and graceful degradation
- Validates PID and process existence before each collection
- Output files timestamped with thread count for easy correlation
- Run as splunk user or root to access process memory
- Consider log rotation if running long-term in production
- Use in conjunction with main splunkd monitoring for complete visibility
