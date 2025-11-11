# KV Store Certificate Verification - Deployment Guide

## Overview
This tool must be run on each KV Store cluster member individually to verify certificate configurations before upgrading from KV Store 4/4.2 to 7.

## Files to Deploy

### Minimum Required Files
```
kv_cert_verifier.py     # Main verification script
requirements.txt        # Python dependencies (if using Python)
kv_cert_verifier.sh      # Bash fallback (if Python unavailable)
splunk_config_checker/  # Required internal package for configuration validation
```

### Complete Package
```
kv_cert_verifier.py     # Main verification script
kv_cert_verifier.sh      # Bash fallback script
requirements.txt       # Python dependencies
README.md              # Full documentation
GETTING_STARTED.md     # Quick start guide
test_tool.sh          # Tool validation script
splunk_config_checker/ # Required internal package (must be deployed)
```

## Deployment Steps

### Step 1: Copy Files to Each KV Store Member
```bash
# Copy tool and dependencies to each cluster member
scp -r kvcertverify/ splunk_config_checker/ user@kvstore-member-1:/tmp/
scp -r kvcertverify/ splunk_config_checker/ user@kvstore-member-2:/tmp/
scp -r kvcertverify/ splunk_config_checker/ user@kvstore-member-3:/tmp/

# Ensure Python can find the splunk_config_checker package
export PYTHONPATH=/tmp:$PYTHONPATH  # Add this to your shell profile if needed
```

### Step 2: Run Verification on Each Member

#### Option A: Using Splunk's Python (Recommended)
```bash
# On each KV Store member
cd /tmp/kvcertverify
chmod +x kv_cert_verifier.py

# Run with Splunk's Python
/opt/splunk/bin/python kv_cert_verifier.py /opt/splunk --verbose
```

#### Option B: Using System Python
```bash
# On each KV Store member (if cryptography library available)
cd /tmp/kvcertverify
pip install -r requirements.txt
python3 kv_cert_verifier.py /opt/splunk --verbose
```

#### Option C: Using Bash Fallback
```bash
# On each KV Store member (minimal dependencies)
cd /tmp/kvcertverify
chmod +x kv_cert_verifier.sh
./kv_cert_verifier.sh /opt/splunk --verbose
```

### Step 3: Collect Results from All Members

```bash
# Run on each member and save results
for member in kvstore-member-1 kvstore-member-2 kvstore-member-3; do
    echo "=== Checking $member ===" >> kv_verification_results.txt
    ssh $member "cd /tmp/kvcertverify && /opt/splunk/bin/python kv_cert_verifier.py /opt/splunk" >> kv_verification_results.txt
    echo "" >> kv_verification_results.txt
done
```

## Why Each Member Needs Individual Verification

### 1. **Local Configuration Files**
- Each member has its own `/opt/splunk/etc/system/local/server.conf`
- Certificate paths and settings may differ between members
- Local overrides can vary per member

### 2. **Certificate File Locations**
- Certificate files might be in different locations on each member
- Different members might use different CA files
- File permissions and accessibility vary per member

### 3. **Network Configuration**
- SAN requirements (localhost/127.0.0.1) must be met on each member
- Each member needs to validate its own certificate chain
- SSL settings must be correct on every member

### 4. **Version Compatibility**
- Different members might run different Splunk versions
- Version-specific certificate requirements vary
- Upgrade readiness must be verified per member

## Cluster-Wide Considerations

### Certificate Consistency
While each member is verified individually, ensure:
- All members use compatible certificate formats
- CA chains are consistent across the cluster
- SSL settings are uniform (unless intentionally different)

### Common Issues Across Members
- **Inconsistent CA files**: Some members might have incomplete CA chains
- **Mixed certificate formats**: Some members might use different formats
- **Version mismatches**: Different Splunk versions across members
- **Permission issues**: Certificate files not readable on some members

## Automation Script Example

```bash
#!/bin/bash
# verify_kv_cluster.sh - Verify all KV Store members

MEMBERS=("kvstore-1" "kvstore-2" "kvstore-3")
SPLUNK_HOME="/opt/splunk"
TOOL_PATH="/tmp/kvcertverify"

for member in "${MEMBERS[@]}"; do
    echo "=== Verifying KV Store Member: $member ==="
    
    # Copy tool if needed
    scp -r kvcertverify/ $member:$TOOL_PATH/
    
    # Run verification
    ssh $member "cd $TOOL_PATH && $SPLUNK_HOME/bin/python kv_cert_verifier.py $SPLUNK_HOME --verbose" | tee "results_$member.log"
    
    echo "Results saved to: results_$member.log"
    echo ""
done

echo "All KV Store members verified. Check individual result files."
```

## Post-Verification Actions

### If All Members Pass
- Proceed with KV Store upgrade process
- Ensure all members are stopped/started in correct sequence

### If Any Member Fails
- Fix certificate issues on failing members
- Re-run verification on fixed members
- Do not proceed with upgrade until all members pass

### Common Fixes
- Update certificate formats (PKCS8 for sslConfig)
- Add localhost/127.0.0.1 to SAN extensions
- Set proper certificate purposes (no purpose or dual purpose)
- Enable SSL compression and renegotiation
- Fix certificate file permissions and paths

## Security Considerations

- Run verification with appropriate user permissions
- Ensure certificate files are not copied unnecessarily
- Clean up tool files after verification
- Verify certificate file permissions are correct
- Test in non-production environment first
