# Volume Mapper

Maps Splunk index paths to their underlying filesystem mount points and types.

## Purpose

This tool helps administrators understand how Splunk indexes are distributed across storage volumes and filesystem types for all data lifecycle stages (hot, cold, and frozen). It's particularly useful for:

- Storage capacity planning and monitoring across hot, cold, and frozen tiers
- Performance troubleshooting (identifying which indexes share storage at each tier)
- Ensuring proper storage distribution across mount points for data lifecycle management
- Validating tiered storage configurations during deployment
- Identifying potential I/O bottlenecks when multiple indexes share the same storage
- Understanding data retention and archival storage mappings
- Planning storage migrations and capacity upgrades for specific data tiers

## Requirements

- Splunk Enterprise installation
- Linux operating system
- `findmnt` command (part of util-linux package)
- Read access to `$SPLUNK_HOME/etc/splunk-launch.conf`
- Splunk btool functionality

## Usage

```bash
./volmapper.sh [OPTIONS]
```

### Options

- `-h, --hot` - Show hot paths (homePath) only
- `-c, --cold` - Show cold paths (coldPath) only
- `-f, --frozen` - Show frozen paths (coldToFrozenDir) only
- `--help` - Show help message

If no path type options are specified, all path types are shown.

The script automatically:
1. Detects `SPLUNK_HOME` (from environment variable or defaults to `/opt/splunk`)
2. Reads `SPLUNK_DB` from `splunk-launch.conf`
3. Uses Splunk's btool to enumerate all index configurations
4. Maps each index path to its filesystem mount point and type
5. Shows the corresponding stanza name and path type

### Examples

```bash
# Show all path types (default behavior)
./volmapper.sh

# Show only hot paths
./volmapper.sh -h

# Show only cold paths
./volmapper.sh -c

# Show only frozen paths
./volmapper.sh -f

# Show both cold and frozen paths
./volmapper.sh -c -f

# Copy script to Splunk directory and run
cp volmapper.sh /opt/splunk/bin/
cd /opt/splunk/bin
./volmapper.sh --help
```

## Example Output

```
Using SPLUNK_DB: /opt/splunk/var/lib/splunk
----------------------------------------------------------------------
STANZA               PATH TYPE  SPLUNK PATH                                        MOUNT POINT          FSTYPE
----------------------------------------------------------------------
defaultdb            HOT        /opt/splunk/var/lib/splunk/defaultdb/db            /                    ext4
defaultdb            COLD       /opt/splunk/var/lib/splunk/defaultdb/colddb        /                    ext4
historydb            HOT        /opt/splunk/var/lib/splunk/historydb/db            /                    ext4
main                 HOT        /data/splunk/indexes/main/db                       /data                xfs
main                 COLD       /data/splunk/indexes/main/colddb                   /data                xfs
main                 FROZEN     /archive/splunk/main                               /archive             nfs4
security             HOT        /data/splunk/indexes/security/db                   /data                xfs
security             COLD       /data/splunk/indexes/security/colddb               /data                xfs
summary              HOT        /fast-storage/splunk/indexes/summary/db            /fast-storage        nvme
summary              COLD       /slow-storage/splunk/indexes/summary/colddb        /slow-storage        ext4
```

## Notes

- The script resolves `$SPLUNK_DB` variables in index paths to their actual filesystem locations
- Processes indexes with valid homePath, coldPath, and coldToFrozenDir configurations based on selected options
- Mount point and filesystem type information comes from the Linux `findmnt` command
- Shows the stanza name (index name) and path type (HOT/COLD/FROZEN) for easy identification
- If `SPLUNK_HOME` is not set in environment, defaults to `/opt/splunk`
- If `SPLUNK_DB` is not defined in `splunk-launch.conf`, defaults to `$SPLUNK_HOME/var/lib/splunk`
- Requires Splunk to be properly installed and configured to use btool functionality
- Cold and frozen paths may not be configured for all indexes (will only show what's configured)
- Use command line switches to focus on specific data tiers for targeted analysis