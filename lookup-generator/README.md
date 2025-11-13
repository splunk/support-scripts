# Lookup Generator

Generates large test CSV lookup files for Splunk testing and validation. Creates realistic sample data with randomized values for performance testing, ingestion testing, or development purposes.

## Purpose

Quickly create sizeable lookup files with sample data to:

- Test lookup performance in Splunk
- Validate data ingestion pipelines
- Develop and test dashboards with realistic data volumes
- Benchmark search performance with large lookups

## Requirements

- Bash shell
- Standard Unix tools (tr, awk, df)
- `/dev/urandom` for random data generation
- At least 24MB free disk space (14MB target + buffer)

**Compatible with:** Linux and macOS/BSD

## Usage

```bash
./lookup_gen.sh
```

By default, generates `splunk_lookup.csv` with approximately 14MB of data in the current directory.

### Example

```bash
# Generate default lookup file
./lookup_gen.sh

# Output file created: splunk_lookup.csv (~14MB)
```

### Modifying Output

Edit the script to customize:

- `OUTPUT_FILE` - Change output filename (default: `splunk_lookup.csv`)
- `TARGET_SIZE_MB` - Change target file size (default: 14MB)

## Output Format

CSV file with columns:

- `id` - Random 8-character identifier
- `username` - Random 10-character username
- `email` - Generated email address
- `age` - Random age between 18-77
- `country` - Random country (USA, Canada, UK, Germany, France, Australia)

### Sample Output

```csv
id,username,email,age,country
Ab3Xk9pL,Hs8Pq2VnRt,Hs8Pq2VnRt@example.com,45,Canada
Zx7Mn4Qw,Kf6Gh8JcPl,Kf6Gh8JcPl@example.com,32,Germany
```

## Notes

- File size may vary slightly (±1MB) due to row boundaries - script stops when target size is reached
- Script checks available disk space before generating
- Includes safety limit to prevent infinite loops
- Cross-platform compatible (auto-detects OS for correct stat command)
- Useful for testing lookup limits and performance in Splunk
