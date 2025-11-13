# Splunk KV Store Certificate Verification Tool

This tool verifies KV Store certificate configurations for safe upgrades from Splunk KV Store 4/4.2 to 7. It checks all the requirements outlined in Splunk documentation to ensure certificates are properly configured before upgrade.

## Features

- **Comprehensive Certificate Analysis**: Validates certificate formats, purposes, and chain verification
- **Configuration Validation**: Checks `server.conf` settings for both `[sslConfig]` and `[kvstore]` sections
- **Version Compatibility**: Ensures certificate requirements match Splunk version capabilities
- **Multiple Output Formats**: Supports both human-readable and JSON output
- **Dual Implementation**: Python script for comprehensive checks, Bash script for basic validation

## Requirements Verified

### Certificate Format Requirements

- **Certificate structure**: Must contain public key, private key, and CA public key
- **Chain validation**: Server certificates must verify against specified CA

### Certificate Purpose Requirements

- **sslConfig certificates**: Must be signed by given/presented CA
- **kvstore certificates**: Must have no purpose OR be dual purpose (client + server)
- **CA certificates**: Must have no purpose OR be dual purpose (client + server)

### Network Requirements

- **SAN validation**: KV Store certificates must contain 127.0.0.1 or localhost, unless `verifyServerName=false`
- **Hostname validation**: Can be disabled via `verifyServerName=false` setting

### Configuration Requirements

- **SSL Compression**: `allowSslCompression=true` required in `[sslConfig]`
- **SSL Renegotiation**: `allowSslRenegotiation=true` required in `[sslConfig]`
- **CA Completeness**: `sslRootCAPath` must contain ALL CAs used in KV Store cluster

### Version-Specific Requirements

- **Splunk 9.4.3+**: Custom KV Store certificates supported
- **Earlier versions**: Must use default certificates

## Installation

### Prerequisites

**For Python script (recommended):**

```bash
# Python 3.6+ required
pip install -r requirements.txt
```

**For basic bash script:**

```bash
# Only requires standard Unix tools
# OpenSSL recommended for certificate analysis
```

### Dependencies

The Python script requires:

- `splunk_config_checker` - Internal package for configuration validation
- `cryptography` - For certificate parsing and validation
- `configparser` - For parsing Splunk configuration files
- `pathlib` - For path handling (Python 3.4+)

The `splunk_config_checker` package is a required internal dependency that must be deployed alongside this tool. It provides the core configuration validation framework used by the certificate verifier.

## Usage

### Python Script (Comprehensive)

```bash
# Basic usage
python3 kv_cert_verifier.py /opt/splunk

# Verbose output
python3 kv_cert_verifier.py /opt/splunk --verbose

# JSON output
python3 kv_cert_verifier.py /opt/splunk --output json

# Using environment variable
python3 kv_cert_verifier.py $SPLUNK_HOME -v
```

### Bash Script (Basic Checks)

```bash
# Basic usage
./kv_cert_verifier.sh /opt/splunk

# Verbose output
./kv_cert_verifier.sh --verbose /opt/splunk

# Basic checks only (no Python dependencies)
./kv_cert_verifier.sh --check /opt/splunk
```

## Output

### Success Example

```
✓ SSL Config section exists
✓ SSL compression enabled
✓ SSL renegotiation enabled
✓ SSL server certificate valid
✓ SSL certificate chain valid
✓ KV Store server cert valid
✓ KV Store cert purpose correct
✓ KV Store cert SAN correct
✓ KV Store CA cert purpose correct
✓ KV Store certificate chain valid
✓ CA certificates complete
✓ Version compatibility

Checks passed: 12/12

✓ All checks passed! KV Store configuration appears ready for upgrade.
```

### Error Example

```
✗ SSL Config section exists
✓ SSL compression enabled
✗ SSL renegotiation enabled
✗ SSL server certificate valid
✗ SSL certificate chain valid

Checks passed: 1/12

ERRORS (3):
  • allowSslRenegotiation must be set to true in [sslConfig] (current: false)
  • Server certificate file not found: /opt/splunk/etc/auth/server.pem
  • Server certificate chain verification failed for [sslConfig]

✗ Some checks failed. Please review and fix issues before upgrading.
```

## File Structure

```
kvcertverify/
├── kv_cert_verifier.py    # Main Python verification script
├── kv_cert_verifier.sh      # Bash companion script
├── requirements.txt       # Python dependencies
└── README.md             # This documentation
```

## Configuration Files Checked

The tool examines the following Splunk configuration files:

1. **`$SPLUNK_HOME/etc/system/default/server.conf`** - Default settings
2. **`$SPLUNK_HOME/etc/system/local/server.conf`** - Local overrides

### Key Sections Analyzed

#### [sslConfig] Section

- `allowSslCompression` - Must be `true`
- `allowSslRenegotiation` - Must be `true`
- `serverCert` - Server certificate path
- `caCertFile` or `sslRootCAPath` - CA certificate path

#### [kvstore] Section

- `serverCert` - KV Store server certificate
- `caCertFile` or `sslRootCAPath` - KV Store CA certificate
- `verifyServerName` - Hostname verification setting

## Certificate Analysis

### Format Validation

- **PEM Format**: Checks for proper BEGIN/END markers
- **PKCS8**: Validates private key format for sslConfig
- **PKCS12**: Supports PKCS12 format (Windows environments)
- **Certificate Count**: Verifies CA files contain expected certificates

### Purpose Validation

- **Key Usage**: Analyzes X.509 Key Usage extension
- **Extended Key Usage**: Checks for Server Auth and Client Auth purposes
- **No Purpose**: Validates certificates without purpose restrictions

### Chain Validation

- **Signature Verification**: Confirms certificates signed by specified CA
- **Issuer Matching**: Validates certificate issuer against CA subject
- **Trust Chain**: Ensures complete certificate chain validation

## Troubleshooting

### Common Issues

**1. Certificate Not Found**

```
ERROR: Server certificate file not found: /path/to/cert.pem
```

_Solution_: Verify certificate path in server.conf and file permissions

**2. Certificate Purpose Mismatch**

```
ERROR: KV Store server certificate must have no purpose or be dual purpose
```

_Solution_: Generate certificates without Extended Key Usage or with both Server Auth and Client Auth

**3. SAN Missing Localhost**

```
ERROR: KV Store server certificate SAN must contain 127.0.0.1 or localhost
```

_Solution_: Add localhost/127.0.0.1 to SAN or set `verifyServerName=false`

**4. SSL Settings Missing**

```
ERROR: allowSslCompression must be set to true in [sslConfig]
```

_Solution_: Add required SSL settings to server.conf:

```ini
[sslConfig]
allowSslCompression = true
allowSslRenegotiation = true
```

### Version-Specific Issues

**Splunk < 9.4.3**: Custom certificates may not be supported

- Use default Splunk certificates
- Verify default certificate locations

**Splunk >= 9.4.3**: Custom certificates supported

- Follow certificate format requirements
- Ensure proper certificate purposes

## Exit Codes

- **0**: All checks passed successfully
- **1**: One or more checks failed or errors occurred

## Contributing

To extend the tool:

1. **Add new checks**: Extend the verification methods in `CertificateVerifier` class
2. **Improve certificate analysis**: Enhance certificate parsing in `load_certificate()` method
3. **Add configuration support**: Extend `parse_server_conf()` for additional settings
4. **Version handling**: Update `check_version_compatibility()` for new Splunk versions

## References

- [Splunk KV Store Documentation](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.0/administer-the-app-key-value-store/preparing-custom-certificates-for-use-with-kv-store)
- [Splunk SSL Certificate Requirements](https://docs.splunk.com/Documentation/Splunk/latest/Security/AboutsecuringyourSplunkconfigurationwithSSL)
- [X.509 Certificate Standards](https://tools.ietf.org/html/rfc5280)

## License

This tool is provided as-is for Splunk environment verification purposes. Use at your own discretion and always test in non-production environments first.
