# Splunkd Pstacks Threads Monitor

Monitors main splunkd process thread count and automatically collects pstack dumps when thread count exceeds 500, indicating potential lock contention, file descriptor leaks, or hung processes.

## Purpose

Automatically capture user-space stack traces during thread exhaustion to:

- Diagnose thread count spikes and exhaustion issues on indexers
- Detect lock contention and deadlocks in splunkd
- Identify file descriptor leaks causing thread accumulation
- Capture diagnostic data automatically without manual intervention when threshold exceeded
- Correlate thread spikes with application-level behavior

## Requirements

- **Linux only** (uses `/proc` filesystem)
- **pstack or gdb** installed
  - RHEL/CentOS: `yum install gdb`
  - Ubuntu/Debian: `apt install gdb`
- Splunk Enterprise installation at `/opt/splunk` (or edit `SPLUNK_HOME` variable)
- Access to read splunkd process memory (run as splunk user or root)

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
pstack_splunkd-<pid>-<threads>-<unix_timestamp>.out
```

Example: `pstack_splunkd-12345-753-1705335825.out`

### Example Output

```
Thread 1 (LWP 12345):
#0  0x00007f8a1234abcd in poll () from /lib64/libc.so.6
#1  0x000000000123456 in TcpInputProc::run()
#2  0x000000000234567 in ThreadPoolImpl::workerThread()
#3  0x00007f8a1345bcde in start_thread () from /lib64/libpthread.so.0

Thread 2 (LWP 12346):
...
```

## Monitoring with Splunk

### Monitor Thread Counts

```spl
| tstats
  max(data.t_count) as data.t_count
  where index=_introspection host IN(*idx*) sourcetype::splunk_resource_usage
  by host _time span=60s
| timechart span=60s max(data.t_count) as "thread count" by host limit=0
| eval danger=500
```

### Alert on High Thread Counts

```spl
index=_introspection host IN (*idx*) sourcetype=splunk_resource_usage
| stats max("data.t_count") as thread_count by host
| search thread_count>500
```

## Deployment Options

**Option A:** Alert-based collection
- Create alert to notify when any indexer exceeds 500 threads
- Run every ~15 minutes
- Manually deploy script to affected host when alerted

**Option B:** Proactive monitoring (recommended)
- Install script on all indexers
- Run in background continuously
- Create alert to notify which hosts to fetch pstacks from
- Collect pstacks + generate diag for Splunk Support

## Notes

- **Threshold of 500 threads** - typically indicates issues (lock contention, fd leaks, hung processes)
- Normal Splunk indexer: ~200-300 threads under load
- Samples every 1 second - minimal overhead when below threshold
- Only collects pstack when threshold exceeded - no output otherwise
- Script includes robust error handling and graceful degradation
- Validates PID and process existence before each collection
- Output files timestamped with thread count for easy correlation
- Run as splunk user or root to access process memory
- Consider log rotation if running long-term in production
