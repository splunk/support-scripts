# Test Peers

Tests network connectivity to all Splunk cluster peers on port 8089. Automatically discovers peer nodes from distributed search configuration and validates TCP connectivity.

## Purpose

Quickly diagnose network connectivity issues in Splunk distributed environments by:
- Auto-discovering all configured search peers
- Testing TCP connectivity on management port (8089)
- Identifying unreachable or misconfigured peers
- Validating cluster communication before troubleshooting

## Requirements

- **Bash shell** (not sh/dash - uses bash-specific `/dev/tcp` feature)
- Splunk Enterprise installation with configured distributed search
- `splunk` command must be in PATH (or run from `$SPLUNK_HOME/bin`)
- Network access to peer nodes

## Usage

```bash
./testpeers.sh
```

Script must run on a Splunk instance with configured search peers (typically a search head).

### Example

```bash
# Test all peers from current Splunk instance
cd /path/to/test-peers
./testpeers.sh

# Output:
# Testing connectivity to port 8089 on all discovered peers...
#
# Connecting to indexer1.example.com:8089... Success
# Connecting to indexer2.example.com:8089... Failed
# Connecting to indexer3.example.com:8089... Success
```

## How It Works

1. Queries `distsearch.conf` using `splunk btool` to discover configured peers
2. Extracts hostnames from peer URIs
3. Tests TCP connectivity to port 8089 on each peer (2 second timeout)
4. Reports success or failure for each connection

## Output

For each discovered peer:
- **Success** - Port 8089 is reachable
- **Failed** - Port 8089 is unreachable (network issue, firewall, or peer down)

Summary line shows total succeeded and failed counts.

### Example Output

```
Testing connectivity to port 8089 on all discovered peers...

Connecting to indexer1.example.com:8089... Success
Connecting to indexer2.example.com:8089... Failed
Connecting to indexer3.example.com:8089... Success

Results: 2 succeeded, 1 failed
```

## Exit Codes

- **0** - All peers reachable
- **1** - `splunk` command not found
- **2** - No peers configured
- **3** - One or more peers unreachable

## Notes

- Requires `splunk` command in PATH (not just `btool`)
- Tests management port 8089 only (default Splunk management port)
- 2-second timeout per peer prevents hanging on unreachable hosts
- Uses bash-specific `/dev/tcp` feature for connection testing
- Useful for troubleshooting distributed search connectivity issues
