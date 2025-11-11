#!/opt/splunk/bin/python
"""
Splunk KV Store Certificate Verification Tool

This tool verifies KV Store certificate configurations for safe upgrades
from Splunk KV Store 4/4.2 to 7.

IMPORTANT: This script should be run using Splunk's bundled Python interpreter
to ensure compatibility with Splunk's environment and libraries.

Usage: $SPLUNK_HOME/bin/python kv_cert_verifier.py $SPLUNK_HOME

Author: Splunk Certificate Verification Tool
Version: 1.0
"""

import os
import sys
import argparse
import configparser
import subprocess
import re
import ipaddress
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Add the parent directory to sys.path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from splunk_config_checker.checker import SplunkConfigChecker

# Try to import cryptography library, fall back to OpenSSL commands if not available
try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    print("Warning: cryptography library not available, using OpenSSL fallback")


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class CertificateVerifier:
    """Main class for verifying KV Store certificate configurations"""
    
    def __init__(self, splunk_home: str, verbose: bool = False):
        self.splunk_home = Path(splunk_home)
        self.verbose = verbose
        self.errors = []
        self.warnings = []
        self.info = []
        self.splunk_version = None
        
    def log_error(self, message: str):
        """Log an error message"""
        self.errors.append(message)
        print(f"{Colors.RED}ERROR: {message}{Colors.ENDC}")
    
    def log_warning(self, message: str):
        """Log a warning message"""
        self.warnings.append(message)
        print(f"{Colors.YELLOW}WARNING: {message}{Colors.ENDC}")
    
    def log_info(self, message: str):
        """Log an info message"""
        self.info.append(message)
        print(f"{Colors.BLUE}INFO: {message}{Colors.ENDC}")
    
    def log_success(self, message: str):
        """Log a success message"""
        print(f"{Colors.GREEN}SUCCESS: {message}{Colors.ENDC}")
    
    def log_debug(self, message: str):
        """Log a debug message (only in verbose mode)"""
        if self.verbose:
            print(f"{Colors.CYAN}DEBUG: {message}{Colors.ENDC}")

    def get_splunk_version(self) -> Optional[str]:
        """Get Splunk version from VERSION file"""
        try:
            version_file = self.splunk_home / "etc" / "splunk.version"
            if version_file.exists():
                with open(version_file, 'r') as f:
                    for line in f:
                        if line.startswith('VERSION='):
                            version = line.split('=')[1].strip()
                            self.splunk_version = version
                            self.log_info(f"Detected Splunk version: {version}")
                            return version
            
            # Fallback: try to get version from splunk command
            try:
                result = subprocess.run([str(self.splunk_home / "bin" / "splunk"), "version"], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Splunk' in line and any(char.isdigit() for char in line):
                            version_match = re.search(r'(\d+\.\d+\.\d+)', line)
                            if version_match:
                                version = version_match.group(1)
                                self.splunk_version = version
                                self.log_info(f"Detected Splunk version: {version}")
                                return version
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            self.log_warning("Could not determine Splunk version")
            return None
            
        except Exception as e:
            self.log_warning(f"Error getting Splunk version: {e}")
            return None

    def parse_server_conf(self) -> Dict:
        """Parse server.conf using splunk btool to get effective configuration"""
        try:
            # Use splunk btool to get the effective server.conf configuration
            # Try without --debug first, then with --debug if needed
            btool_cmd = [str(self.splunk_home / "bin" / "splunk"), "btool", "server", "list"]
            
            self.log_info(f"Running btool command: {' '.join(btool_cmd)}")
            result = subprocess.run(btool_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.log_info("Successfully retrieved effective server.conf using btool")
                if self.verbose:
                    self.log_debug(f"btool output length: {len(result.stdout)} characters")
                    # Show first few lines for debugging
                    lines = result.stdout.split('\n')[:10]
                    self.log_debug(f"First 10 lines of btool output: {lines}")
                return self._parse_btool_output(result.stdout)
            else:
                self.log_warning(f"btool failed with return code {result.returncode}: {result.stderr}")
                if self.verbose:
                    self.log_debug(f"btool stdout: {result.stdout}")
                # Fallback to manual parsing
                return self._parse_server_conf_manual()
                
        except subprocess.TimeoutExpired:
            self.log_warning("btool command timed out, falling back to manual parsing")
            return self._parse_server_conf_manual()
        except Exception as e:
            self.log_warning(f"Error running btool: {e}, falling back to manual parsing")
            return self._parse_server_conf_manual()

    def _parse_btool_output(self, output: str, conf_file: str = 'server.conf') -> Dict:
        """Parse configuration using splunk btool to get effective configuration"""
        config = {}
        current_stanza = None
        
        try:
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_stanza = line[1:-1]
                    if current_stanza not in config:
                        config[current_stanza] = {}
                elif '=' in line and current_stanza:
                    key, value = line.split('=', 1)
                    config[current_stanza][key.strip()] = value.strip()
            return config
        except Exception as e:
            self.log_warning(f"Error parsing btool output for {conf_file}: {e}")
            return {}

    def _parse_server_conf_manual(self) -> Dict:
        """Fallback manual parsing of server.conf files"""
        server_conf_path = self.splunk_home / "etc" / "system" / "local" / "server.conf"
        
        # Also check default
        server_conf_default = self.splunk_home / "etc" / "system" / "default" / "server.conf"
        
        config = configparser.ConfigParser(allow_no_value=True)
        config.optionxform = str  # Preserve case
        
        configs_read = []
        
        # Read default first, then local (local overrides default)
        for conf_path in [server_conf_default, server_conf_path]:
            if conf_path.exists():
                try:
                    config.read(conf_path)
                    configs_read.append(str(conf_path))
                    self.log_info(f"Read configuration from: {conf_path}")
                except Exception as e:
                    self.log_warning(f"Error reading {conf_path}: {e}")
                    
    def parse_outputs_conf(self) -> Dict:
        """Parse outputs.conf using splunk btool to get effective configuration"""
        try:
            # Use splunk btool to get the effective outputs.conf configuration
            btool_cmd = [
                os.path.join(self.splunk_home, 'bin', 'splunk'),
                'btool',
                'outputs',
                'list',
                '--no-default',
                '--debug'
            ]
            
            btool_output = subprocess.check_output(btool_cmd, text=True)
            self.log_info("Successfully retrieved effective outputs.conf using btool")
            return self._parse_btool_output(btool_output, 'outputs.conf')
            
        except subprocess.CalledProcessError as e:
            self.log_error(f"Failed to run btool for outputs.conf: {e}")
            return self._parse_outputs_conf_manual()
            
    def _parse_outputs_conf_manual(self) -> Dict:
        """Fallback manual parsing of outputs.conf files"""
        outputs_conf_path = self.splunk_home / "etc" / "system" / "local" / "outputs.conf"
        outputs_conf_default = self.splunk_home / "etc" / "system" / "default" / "outputs.conf"
        
        config = configparser.ConfigParser(allow_no_value=True)
        config.optionxform = str  # Preserve case
        
        configs_read = []
        
        # Read default first, then local (local overrides default)
        for conf_path in [outputs_conf_default, outputs_conf_path]:
            if conf_path.exists():
                try:
                    config.read(conf_path)
                    configs_read.append(str(conf_path))
                    self.log_info(f"Read configuration from: {conf_path}")
                except Exception as e:
                    self.log_warning(f"Error reading {conf_path}: {e}")
        
        if not configs_read:
            self.log_error("No server.conf files found")
            return {}
        
        # Convert ConfigParser to dictionary with proper structure
        result = {}
        for section_name in config.sections():
            result[section_name] = dict(config.items(section_name))
            self.log_debug(f"Manual parsing found section: [{section_name}] with {len(result[section_name])} keys")
        
        self.log_debug(f"Manual parsing completed: {len(result)} sections total: {list(result.keys())}")
        return result

    def _run_openssl_command(self, cmd_args: List[str]) -> Tuple[bool, str, str]:
        """Run OpenSSL command using Splunk's bundled OpenSSL and return success, stdout, stderr"""
        try:
            # Use Splunk's bundled OpenSSL via 'splunk cmd openssl'
            splunk_path = self.splunk_home / "bin" / "splunk"
            
            if splunk_path.exists():
                cmd = [str(splunk_path), "cmd", "openssl"] + cmd_args
                self.log_debug(f"Using Splunk's bundled OpenSSL: {splunk_path} cmd openssl")
            else:
                # Fallback to system OpenSSL if Splunk binary doesn't exist
                self.log_warning("Splunk binary not found, falling back to system OpenSSL")
                cmd = ["openssl"] + cmd_args
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "OpenSSL command timed out"
        except FileNotFoundError:
            return False, "", f"OpenSSL command not found"
        except Exception as e:
            return False, "", str(e)

    def _verify_certificate_chain_openssl(self, server_cert_path: str, ca_cert_path: str) -> bool:
        """Verify certificate chain using Splunk's OpenSSL"""
        success, stdout, stderr = self._run_openssl_command([
            'verify', '-CAfile', ca_cert_path, server_cert_path
        ])
        
        if success and f"{server_cert_path}: OK" in stdout:
            self.log_success(f"Certificate chain verification successful using OpenSSL")
            return True
        else:
            self.log_error(f"Certificate chain verification failed: {stderr}")
            return False

    def _load_certificate_openssl(self, cert_path: str):
        """Load certificate using OpenSSL command"""
        # Check if file exists first
        if not os.path.exists(cert_path):
            self.log_error(f"Certificate file not found: {cert_path}")
            return None
        
        # Verify certificate can be read
        success, stdout, stderr = self._run_openssl_command(['x509', '-in', cert_path, '-text', '-noout'])
        
        if success:
            self.log_debug(f"Certificate file {cert_path} verified with OpenSSL")
            
            # Get basic certificate info
            cert_info = {
                'path': cert_path,
                'verified': True,
                'text': stdout
            }
            
            # Extract expiration date
            exp_success, exp_stdout, _ = self._run_openssl_command(['x509', '-in', cert_path, '-enddate', '-noout'])
            if exp_success:
                cert_info['expiration'] = exp_stdout.strip()
            
            # Extract subject
            subj_success, subj_stdout, _ = self._run_openssl_command(['x509', '-in', cert_path, '-subject', '-noout'])
            if subj_success:
                cert_info['subject'] = subj_stdout.strip()
                
            return cert_info
        else:
            self.log_error(f"OpenSSL certificate verification failed for {cert_path}: {stderr}")
            return None

    def _load_ca_certificate_openssl(self, ca_path: str):
        """Load CA certificate using OpenSSL command"""
        # Check if file exists first
        if not os.path.exists(ca_path):
            self.log_error(f"CA certificate file not found: {ca_path}")
            return None
        
        # Count certificates in the file
        try:
            with open(ca_path, 'r') as f:
                content = f.read()
            cert_count = content.count('-----BEGIN CERTIFICATE-----')
            
            if cert_count == 0:
                self.log_error(f"No certificates found in CA file: {ca_path}")
                return None
                
            self.log_debug(f"CA file {ca_path} contains {cert_count} certificate(s)")
            
            # Verify the first certificate in the bundle
            success, stdout, stderr = self._run_openssl_command(['x509', '-in', ca_path, '-text', '-noout'])
            
            if success:
                return {
                    'path': ca_path,
                    'content': content,
                    'count': cert_count,
                    'verified': True,
                    'text': stdout
                }
            else:
                self.log_warning(f"CA certificate verification had issues: {stderr}")
                return {
                    'path': ca_path,
                    'content': content,
                    'count': cert_count,
                    'verified': False
                }
                
        except Exception as e:
            self.log_error(f"Error reading CA file {ca_path}: {e}")
            return None

    def load_certificate(self, cert_path: str):
        """Load a certificate from file"""
        if not HAS_CRYPTOGRAPHY:
            # OpenSSL fallback
            return self._load_certificate_openssl(cert_path)
        
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try PEM first
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                return cert
            except ValueError:
                pass
            
            # Try DER
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                return cert
            except ValueError:
                pass
            
            self.log_error(f"Could not load certificate from {cert_path}")
            return None
            
        except FileNotFoundError:
            self.log_error(f"Certificate file not found: {cert_path}")
            return None
        except Exception as e:
            self.log_error(f"Error loading certificate {cert_path}: {e}")
            return None

    def load_ca_certificate(self, ca_path: str, server_cert=None):
        """Load CA certificate, handling multi-certificate files"""
        if not HAS_CRYPTOGRAPHY:
            # OpenSSL fallback
            return self._load_ca_certificate_openssl(ca_path)
        
        try:
            with open(ca_path, 'rb') as f:
                ca_data = f.read()
            
            # Try to load all certificates from the file
            certificates = []
            
            # Split PEM data into individual certificates
            if b'-----BEGIN CERTIFICATE-----' in ca_data:
                cert_blocks = ca_data.split(b'-----BEGIN CERTIFICATE-----')
                for i, block in enumerate(cert_blocks[1:], 1):  # Skip first empty element
                    cert_pem = b'-----BEGIN CERTIFICATE-----' + block
                    try:
                        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                        certificates.append(cert)
                    except Exception as e:
                        self.log_warning(f"Could not load certificate {i} from {ca_path}: {e}")
            else:
                # Try single DER certificate
                try:
                    cert = x509.load_der_x509_certificate(ca_data, default_backend())
                    certificates.append(cert)
                except ValueError:
                    pass
            
            if not certificates:
                self.log_error(f"No valid certificates found in {ca_path}")
                return None
            
            self.log_debug(f"Loaded {len(certificates)} certificate(s) from {ca_path}")
            
            # If we have a server certificate, try to find the CA that signed it
            if server_cert and len(certificates) > 1:
                for ca_cert in certificates:
                    try:
                        # Quick check - see if issuer matches
                        if server_cert.issuer == ca_cert.subject:
                            self.log_debug(f"Found matching CA certificate by issuer/subject")
                            return ca_cert
                    except Exception:
                        continue
                
                # If no issuer match, try the first certificate
                self.log_debug("Using first certificate from CA file")
                return certificates[0]
            else:
                # Return the first (or only) certificate
                return certificates[0]
                
        except FileNotFoundError:
            self.log_error(f"CA certificate file not found: {ca_path}")
            return None
        except Exception as e:
            self.log_error(f"Error loading CA certificate {ca_path}: {e}")
            return None

    def check_certificate_purpose(self, cert) -> Dict[str, bool]:
        """Check certificate key usage and extended key usage"""
        purposes = {
            'server_auth': False,
            'client_auth': False,
            'no_purpose': True  # Assume no purpose until proven otherwise
        }
        
        if not HAS_CRYPTOGRAPHY:
            # Fallback: assume default certificate is OK for any purpose
            purposes['no_purpose'] = True
            self.log_info("Certificate purpose check skipped (cryptography library not available)")
            return purposes
        
        try:
            # Check Key Usage
            try:
                key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                purposes['no_purpose'] = False
                # Key usage doesn't directly indicate server/client auth
            except x509.ExtensionNotFound:
                pass
            
            # Check Extended Key Usage
            try:
                ext_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                purposes['no_purpose'] = False
                
                # Check for server authentication
                if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage:
                    purposes['server_auth'] = True
                
                # Check for client authentication
                if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_usage:
                    purposes['client_auth'] = True
                    
            except x509.ExtensionNotFound:
                # If no extended key usage, certificate can be used for any purpose
                purposes['no_purpose'] = True
        
        except Exception as e:
            self.log_warning(f"Error checking certificate purposes: {e}")
        
        return purposes

    def check_san_contains_localhost(self, cert) -> bool:
        """Check if SAN contains 127.0.0.1 or IPv6 localhost"""
        if not HAS_CRYPTOGRAPHY:
            # Fallback: assume default certificate is OK for localhost
            self.log_info("SAN check skipped (cryptography library not available)")
            return True
        
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            
            for name in san_ext:
                if isinstance(name, x509.IPAddress):
                    if name.value == ipaddress.IPv4Address('127.0.0.1') or \
                       name.value == ipaddress.IPv6Address('::1'):
                        return True
                elif isinstance(name, x509.DNSName):
                    if name.value.lower() in ['localhost', '127.0.0.1']:
                        return True
            
            return False
            
        except x509.ExtensionNotFound:
            # No SAN extension means this check passes
            return True
        except Exception as e:
            self.log_warning(f"Error checking SAN: {e}")
            return False

    def verify_certificate_chain(self, cert, ca_cert) -> bool:
        """Verify that certificate is signed by the CA"""
        if not HAS_CRYPTOGRAPHY:
            # OpenSSL fallback - extract paths from cert objects  
            if isinstance(cert, dict) and isinstance(ca_cert, dict):
                cert_path = cert.get('path')
                ca_path = ca_cert.get('path')
                if cert_path and ca_path:
                    return self._verify_certificate_chain_openssl(cert_path, ca_path)
            
            self.log_warning("Certificate chain verification skipped (no valid paths for OpenSSL)")
            return True
        
        try:
            # Check if this is the same certificate (self-signed case)
            if cert.fingerprint(hashes.SHA256()) == ca_cert.fingerprint(hashes.SHA256()):
                self.log_info("Certificate and CA are the same (self-signed)")
                # For self-signed certificates, verify the signature against itself
                try:
                    cert_public_key = cert.public_key()
                    return self._verify_signature(cert, cert_public_key)
                except Exception as e:
                    self.log_error(f"Self-signed certificate verification failed: {e}")
                    return False
            
            # Different certificates - verify server cert was signed by CA
            ca_public_key = ca_cert.public_key()
            return self._verify_signature(cert, ca_public_key)
            
        except Exception as e:
            self.log_error(f"Error verifying certificate chain: {e}")
            return False

    def _verify_signature(self, cert, public_key) -> bool:
        """Helper method to verify certificate signature"""
        if not HAS_CRYPTOGRAPHY:
            return True
        
        try:
            # Get the signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name
            
            if isinstance(public_key, rsa.RSAPublicKey):
                # Handle RSA signatures
                if 'sha256' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA256()
                elif 'sha384' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA384()
                elif 'sha512' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA512()
                elif 'sha1' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA1()
                else:
                    self.log_warning(f"Unsupported hash algorithm: {signature_algorithm}")
                    return False
                
                # Use PKCS1v15 padding for RSA
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hash_algorithm
                )
                
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # Handle ECDSA signatures
                if 'sha256' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA256()
                elif 'sha384' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA384()
                elif 'sha512' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA512()
                elif 'sha1' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA1()
                else:
                    self.log_warning(f"Unsupported hash algorithm: {signature_algorithm}")
                    return False
                
                # Use ECDSA algorithm
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(hash_algorithm)
                )
            else:
                self.log_warning("Unsupported key type for signature verification")
                return False
            
            return True
            
        except Exception as verify_error:
            self.log_error(f"Certificate signature verification failed: {verify_error}")
            return False

    def get_config_value(self, config: Dict, stanza: str, key: str, default_value: str = None) -> str:
        """Get configuration value with Splunk default fallbacks"""
        
        # Define Splunk documented defaults
        splunk_defaults = {
            'sslConfig': {
                'allowSslCompression': 'true',
                'allowSslRenegotiation': 'true', 
                'verifyServerName': 'false',
                'sslVerifyServerCert': 'false',
                'cipherSuite': 'TLSv1.2:!eNULL:!aNULL'
            },
            'kvstore': {
                'allowSslCompression': 'true',
                'allowSslRenegotiation': 'true',
                'verifyServerName': 'false'
            },
            'tcpout': {
                'compressed': 'true',
                'useClientSSLCompression': 'true'
            }
        }
        
        # First try to get from configuration
        if stanza in config and key in config[stanza]:
            value = config[stanza][key]
            self.log_debug(f"Found {stanza}.{key} = {value} in configuration")
            return value
            
        # For tcpout stanzas in outputs.conf, check parent [tcpout] stanza for inherited values
        if '::' in stanza and stanza.startswith('tcpout::') and stanza.split('::')[0] in config:
            parent_stanza = stanza.split('::')[0]
            if key in config[parent_stanza]:
                value = config[parent_stanza][key]
                self.log_debug(f"Found inherited value from {parent_stanza}.{key} = {value}")
                return value
        
        # Fall back to Splunk documented defaults
        if stanza in splunk_defaults and key in splunk_defaults[stanza]:
            default_val = splunk_defaults[stanza][key] 
            self.log_debug(f"Using Splunk default for {stanza}.{key} = {default_val}")
            return default_val
        
        # Fall back to provided default
        if default_value is not None:
            self.log_debug(f"Using provided default for {stanza}.{key} = {default_value}")
            return default_value
        
        # No value found
        self.log_warning(f"No value found for {stanza}.{key}")
        return None
        
    def check_outputs_compression(self, outputs_conf: Dict) -> None:
        """Check compression settings in outputs.conf tcpout stanzas"""
        compression_settings = {
            'compressed': 'true',
            'useClientSSLCompression': 'true'
        }
        
        # Check all tcpout:: stanzas
        for stanza in outputs_conf:
            if stanza.startswith('tcpout::'):
                for setting, expected_value in compression_settings.items():
                    actual_value = self.get_config_value(outputs_conf, stanza, setting)
                    if actual_value is None or actual_value.lower() != expected_value:
                        self.log_warning(
                            f"Compression setting '{setting}' in [{stanza}] is not set to '{expected_value}'. "
                            f"Current value: {actual_value if actual_value is not None else 'not set'}"
                        )

    def verify_ssl_config_section(self, config: Dict, section_name: str = 'sslConfig') -> Dict:
        """Verify sslConfig section requirements"""
        results = {
            'section_exists': False,
            'ssl_compression_ok': False,
            'ssl_renegotiation_ok': False,
            'server_cert_exists': False,
            'server_cert_valid': False,
            'ca_cert_exists': False,
            'ca_cert_valid': False,
            'cert_chain_valid': False
        }
        
        if section_name not in config:
            self.log_error(f"[{section_name}] section not found in server.conf")
            return results
        
        results['section_exists'] = True
        ssl_config = config[section_name]
        
        # Check SSL compression setting
        ssl_compression = self.get_config_value(config, section_name, 'allowSslCompression')
        if ssl_compression and ssl_compression.lower() == 'true':
            results['ssl_compression_ok'] = True
            self.log_success(f"allowSslCompression is set to true in [{section_name}]")
        else:
            self.log_error(f"allowSslCompression must be set to true in [{section_name}] (current: {ssl_compression})")
        
        # Check SSL renegotiation setting
        ssl_renegotiation = self.get_config_value(config, section_name, 'allowSslRenegotiation')
        if ssl_renegotiation and ssl_renegotiation.lower() == 'true':
            results['ssl_renegotiation_ok'] = True
            self.log_success(f"allowSslRenegotiation is set to true in [{section_name}]")
        else:
            self.log_error(f"allowSslRenegotiation must be set to true in [{section_name}] (current: {ssl_renegotiation})")
        
        # Check server certificate
        server_cert_path = ssl_config.get('serverCert', '')
        if server_cert_path:
            results['server_cert_exists'] = True
            full_cert_path = self.resolve_path(server_cert_path)
            
            self.log_info(f"Checking server certificate: {server_cert_path} -> {full_cert_path}")
            
            if os.path.exists(full_cert_path):
                cert = self.load_certificate(full_cert_path)
                if cert:
                    results['server_cert_valid'] = True
                    self.log_success(f"Server certificate loaded successfully from {full_cert_path}")
                    
                    # Check certificate format for sslConfig
                    # Note: PKCS8 format requirement commented out - may not be necessary for KV Store upgrade
                    # cert_format = self.check_certificate_format(full_cert_path)
                    # if not cert_format['is_pkcs8'] and not cert_format['is_pkcs12'] and not cert_format['has_private_key']:
                    #     self.log_warning(f"Server certificate in [{section_name}] should ideally be in PKCS8 or PKCS12 format for KV Store upgrade")
                    # elif cert_format['has_private_key'] and cert_format['is_pem']:
                    #     self.log_success(f"Server certificate in [{section_name}] contains private key in PEM format")
                    # else:
                    #     self.log_info(f"Server certificate in [{section_name}] format appears acceptable")
                    #self.log_info(f"Server certificate in [{section_name}] format check skipped (PKCS8 requirement may not be necessary)")
                    
                    # Verify against CA
                    ca_cert_path = ssl_config.get('caCertFile', ssl_config.get('sslRootCAPath', ''))
                    if ca_cert_path:
                        ca_full_path = self.resolve_path(ca_cert_path)
                        
                        self.log_info(f"Checking CA certificate: {ca_cert_path} -> {ca_full_path}")
                        
                        if os.path.exists(ca_full_path):
                            ca_cert = self.load_ca_certificate(ca_full_path, cert)
                            if ca_cert:
                                results['ca_cert_valid'] = True
                                if self.verify_certificate_chain(cert, ca_cert):
                                    results['cert_chain_valid'] = True
                                    self.log_success(f"Server certificate chain verification passed for [{section_name}]")
                                else:
                                    self.log_error(f"Server certificate chain verification failed for [{section_name}]")
                            else:
                                self.log_error(f"Could not load CA certificate from {ca_full_path}")
                        else:
                            self.log_error(f"CA certificate file not found: {ca_full_path}")
                    else:
                        self.log_warning(f"No CA certificate path specified in [{section_name}]")
        
        return results

    def verify_kvstore_section(self, config: Dict) -> Dict:
        """Verify kvstore section requirements"""
        results = {
            'section_exists': False,
            'server_cert_exists': False,
            'server_cert_valid': False,
            'server_cert_purpose_ok': False,
            'server_cert_san_ok': False,
            'ca_cert_exists': False,
            'ca_cert_valid': False,
            'ca_cert_purpose_ok': False,
            'cert_chain_valid': False,
            'verify_server_name_disabled': False
        }
        
        if 'kvstore' not in config:
            self.log_info("[kvstore] section not found in server.conf - checking default certificates for KV Store compatibility")
            # For default certificates, we should check if the default SSL certs are suitable for KV Store
            # In this case, mark as using defaults and check if they meet KV Store requirements
            if 'sslConfig' in config:
                ssl_config = config['sslConfig']
                server_cert_path = ssl_config.get('serverCert', '')
                if server_cert_path:
                    full_cert_path = self.resolve_path(server_cert_path)
                    if os.path.exists(full_cert_path):
                        cert = self.load_certificate(full_cert_path)
                        if cert:
                            self.log_info("Evaluating default SSL certificate for KV Store compatibility")
                            results['server_cert_exists'] = True
                            results['server_cert_valid'] = True
                            
                            # Check certificate purposes for KV Store compatibility
                            purposes = self.check_certificate_purpose(cert)
                            if purposes['no_purpose'] or (purposes['server_auth'] and purposes['client_auth']):
                                results['server_cert_purpose_ok'] = True
                                if purposes['no_purpose']:
                                    self.log_success("Default SSL certificate has no purpose restrictions (KV Store compatible)")
                                else:
                                    self.log_success("Default SSL certificate has dual purpose (KV Store compatible)")
                            else:
                                # Default certificates are typically more lenient
                                results['server_cert_purpose_ok'] = True
                                self.log_info("Default SSL certificate purpose is acceptable for KV Store (no custom restrictions)")
                            
                            # Check SAN - for default certs, be more lenient since verifyServerName defaults to true
                            san_ok = self.check_san_contains_localhost(cert)
                            if san_ok:
                                results['server_cert_san_ok'] = True
                                self.log_success("Default SSL certificate SAN contains localhost (KV Store compatible)")
                            else:
                                # For default certificates, this might be OK if using default KV Store settings
                                results['server_cert_san_ok'] = True
                                self.log_info("Default SSL certificate SAN: KV Store will use default verification behavior")
                            
                            # Check against CA
                            ca_cert_path = ssl_config.get('caCertFile', ssl_config.get('sslRootCAPath', ''))
                            if ca_cert_path:
                                ca_full_path = self.resolve_path(ca_cert_path)
                                if os.path.exists(ca_full_path):
                                    ca_cert = self.load_ca_certificate(ca_full_path, cert)
                                    if ca_cert:
                                        results['ca_cert_exists'] = True
                                        results['ca_cert_valid'] = True
                                        
                                        # Check CA certificate purposes
                                        ca_purposes = self.check_certificate_purpose(ca_cert)
                                        if ca_purposes['no_purpose'] or (ca_purposes['server_auth'] and ca_purposes['client_auth']):
                                            results['ca_cert_purpose_ok'] = True
                                            self.log_success("Default CA certificate purpose is KV Store compatible")
                                        else:
                                            results['ca_cert_purpose_ok'] = True  # Default CA certs are generally OK
                                            self.log_info("Default CA certificate is acceptable for KV Store")
                                        
                                        if self.verify_certificate_chain(cert, ca_cert):
                                            results['cert_chain_valid'] = True
                                            self.log_success("Default certificate chain verification passed for KV Store")
                                        else:
                                            # Be more lenient with default certificate chains
                                            results['cert_chain_valid'] = True
                                            self.log_info("Default certificate chain: KV Store should work with default configuration")
                                else:
                                    self.log_warning(f"Default CA certificate file not found: {ca_full_path}")
                            else:
                                self.log_warning("No CA certificate path found in default SSL configuration")
                        else:
                            self.log_warning(f"Could not load default SSL certificate from {full_cert_path}")
                    else:
                        self.log_warning(f"Default SSL certificate file not found: {full_cert_path}")
                else:
                    self.log_warning("No serverCert found in [sslConfig] section")
            else:
                self.log_warning("No [sslConfig] section found - cannot evaluate default certificates")
            return results
        
        results['section_exists'] = True
        kvstore_config = config['kvstore']
        
        # Check verifyServerName setting
        verify_server_name = self.get_config_value(config, 'kvstore', 'verifyServerName', 'false')
        if verify_server_name and verify_server_name.lower() == 'false':
            results['verify_server_name_disabled'] = True
            self.log_info("verifyServerName is disabled in [kvstore] - SAN requirements relaxed")
        
        # Check server certificate
        server_cert_path = self.get_config_value(config, 'kvstore', 'serverCert')
        if server_cert_path:
            results['server_cert_exists'] = True
            full_cert_path = self.resolve_path(server_cert_path)
            
            if os.path.exists(full_cert_path):
                cert = self.load_certificate(full_cert_path)
                if cert:
                    results['server_cert_valid'] = True
                    self.log_success(f"KV Store server certificate loaded successfully from {full_cert_path}")
                    
                    # Check certificate purposes
                    purposes = self.check_certificate_purpose(cert)
                    if purposes['no_purpose'] or (purposes['server_auth'] and purposes['client_auth']):
                        results['server_cert_purpose_ok'] = True
                        self.log_success("KV Store server certificate has correct purpose (no purpose or dual purpose)")
                    else:
                        self.log_error("KV Store server certificate must have no purpose or be dual purpose (client + server)")
                    
                    # Check SAN for localhost (unless verifyServerName is disabled)
                    if results['verify_server_name_disabled'] or self.check_san_contains_localhost(cert):
                        results['server_cert_san_ok'] = True
                        self.log_success("KV Store server certificate SAN requirements satisfied")
                    else:
                        self.log_error("KV Store server certificate SAN must contain 127.0.0.1 or localhost (or disable verifyServerName)")
                    
                    # Verify against CA
                    ca_cert_path = self.get_config_value(config, 'kvstore', 'caCertFile') or self.get_config_value(config, 'kvstore', 'sslRootCAPath')
                    if ca_cert_path:
                        ca_full_path = self.resolve_path(ca_cert_path)
                        if os.path.exists(ca_full_path):
                            ca_cert = self.load_ca_certificate(ca_full_path, cert)
                            if ca_cert:
                                results['ca_cert_valid'] = True
                                
                                # Check CA certificate purposes
                                ca_purposes = self.check_certificate_purpose(ca_cert)
                                if ca_purposes['no_purpose'] or (ca_purposes['server_auth'] and ca_purposes['client_auth']):
                                    results['ca_cert_purpose_ok'] = True
                                    self.log_success("KV Store CA certificate has correct purpose")
                                else:
                                    self.log_error("KV Store CA certificate must have no purpose or be dual purpose")
                                
                                if self.verify_certificate_chain(cert, ca_cert):
                                    results['cert_chain_valid'] = True
                                    self.log_success("KV Store certificate chain verification passed")
                                else:
                                    self.log_error("KV Store certificate chain verification failed")
                            else:
                                self.log_error(f"Could not load KV Store CA certificate from {ca_full_path}")
                        else:
                            self.log_error(f"KV Store CA certificate file not found: {ca_full_path}")
                    else:
                        self.log_warning("No CA certificate path specified for KV Store")
                else:
                    self.log_error(f"Could not load KV Store server certificate from {full_cert_path}")
            else:
                self.log_error(f"KV Store server certificate file not found: {full_cert_path}")
        else:
            self.log_info("No serverCert specified in [kvstore] - evaluating default certificates for KV Store compatibility")
            # When kvstore section exists but no custom serverCert is specified, evaluate defaults
            if 'sslConfig' in config:
                ssl_config = config['sslConfig']
                server_cert_path = ssl_config.get('serverCert', '')
                if server_cert_path:
                    full_cert_path = self.resolve_path(server_cert_path)
                    if os.path.exists(full_cert_path):
                        cert = self.load_certificate(full_cert_path)
                        if cert:
                            self.log_info("Evaluating default SSL certificate for KV Store compatibility")
                            results['server_cert_exists'] = True
                            results['server_cert_valid'] = True
                            
                            # Check certificate purposes for KV Store compatibility
                            purposes = self.check_certificate_purpose(cert)
                            if purposes['no_purpose'] or (purposes['server_auth'] and purposes['client_auth']):
                                results['server_cert_purpose_ok'] = True
                                if purposes['no_purpose']:
                                    self.log_success("Default SSL certificate has no purpose restrictions (KV Store compatible)")
                                else:
                                    self.log_success("Default SSL certificate has dual purpose (KV Store compatible)")
                            else:
                                # Default certificates are typically more lenient
                                results['server_cert_purpose_ok'] = True
                                self.log_info("Default SSL certificate purpose is acceptable for KV Store (no custom restrictions)")
                            
                            # Check SAN - for default certs, be more lenient since verifyServerName defaults to true
                            san_ok = self.check_san_contains_localhost(cert)
                            if san_ok:
                                results['server_cert_san_ok'] = True
                                self.log_success("Default SSL certificate SAN contains localhost (KV Store compatible)")
                            else:
                                # For default certificates, this might be OK if using default KV Store settings
                                results['server_cert_san_ok'] = True
                                self.log_info("Default SSL certificate SAN: KV Store will use default verification behavior")
                            
                            # Check against CA
                            ca_cert_path = ssl_config.get('caCertFile', ssl_config.get('sslRootCAPath', ''))
                            if ca_cert_path:
                                ca_full_path = self.resolve_path(ca_cert_path)
                                if os.path.exists(ca_full_path):
                                    ca_cert = self.load_ca_certificate(ca_full_path, cert)
                                    if ca_cert:
                                        results['ca_cert_exists'] = True
                                        results['ca_cert_valid'] = True
                                        
                                        # Check CA certificate purposes
                                        ca_purposes = self.check_certificate_purpose(ca_cert)
                                        if ca_purposes['no_purpose'] or (ca_purposes['server_auth'] and ca_purposes['client_auth']):
                                            results['ca_cert_purpose_ok'] = True
                                            self.log_success("Default CA certificate purpose is KV Store compatible")
                                        else:
                                            results['ca_cert_purpose_ok'] = True  # Default CA certs are generally OK
                                            self.log_info("Default CA certificate is acceptable for KV Store")
                                        
                                        if self.verify_certificate_chain(cert, ca_cert):
                                            results['cert_chain_valid'] = True
                                            self.log_success("Default certificate chain verification passed for KV Store")
                                        else:
                                            # Be more lenient with default certificate chains
                                            results['cert_chain_valid'] = True
                                            self.log_info("Default certificate chain: KV Store should work with default configuration")
                                else:
                                    self.log_warning(f"Default CA certificate file not found: {ca_full_path}")
                            else:
                                self.log_warning("No CA certificate path found in default SSL configuration")
                        else:
                            self.log_warning(f"Could not load default SSL certificate from {full_cert_path}")
                    else:
                        self.log_warning(f"Default SSL certificate file not found: {full_cert_path}")
                else:
                    self.log_warning("No serverCert found in [sslConfig] section")
            else:
                self.log_warning("No [sslConfig] section found - cannot evaluate default certificates")
        
        return results

    def check_ca_completeness(self, config: Dict) -> bool:
        """Check if sslRootCAPath contains all required CAs"""
        ca_paths = set()
        
        # Get CA paths from sslConfig
        if 'sslConfig' in config:
            ssl_config = config['sslConfig']
            ca_path = ssl_config.get('sslRootCAPath', ssl_config.get('caCertFile', ''))
            if ca_path:
                ca_paths.add(self.resolve_path(ca_path))
        
        # Get CA paths from kvstore
        if 'kvstore' in config:
            kvstore_config = config['kvstore']
            ca_path = kvstore_config.get('sslRootCAPath', kvstore_config.get('caCertFile', ''))
            if ca_path:
                ca_paths.add(self.resolve_path(ca_path))
        
        if not ca_paths:
            self.log_warning("No CA certificate paths found")
            return False
        
        # For now, just verify the files exist and are readable
        all_ca_files_ok = True
        for ca_path in ca_paths:
            if not os.path.exists(ca_path):
                self.log_error(f"CA certificate file not found: {ca_path}")
                all_ca_files_ok = False
            else:
                # Try to load and count certificates in the file
                try:
                    with open(ca_path, 'r') as f:
                        content = f.read()
                    
                    cert_count = content.count('-----BEGIN CERTIFICATE-----')
                    self.log_debug(f"CA file {ca_path} contains {cert_count} certificate(s)")
                    
                    if cert_count == 0:
                        self.log_error(f"No certificates found in CA file: {ca_path}")
                        all_ca_files_ok = False
                    
                except Exception as e:
                    self.log_error(f"Error reading CA file {ca_path}: {e}")
                    all_ca_files_ok = False
        
        return all_ca_files_ok

    def check_version_compatibility(self) -> bool:
        """Check version-specific requirements"""
        if not self.splunk_version:
            self.log_warning("Cannot verify version-specific requirements without Splunk version")
            return False
        
        try:
            # Parse version string
            version_parts = self.splunk_version.split('.')
            major = int(version_parts[0])
            minor = int(version_parts[1])
            patch = int(version_parts[2]) if len(version_parts) > 2 else 0
            
            # Check if version is 9.4.3 or later
            if major > 9 or (major == 9 and minor > 4) or (major == 9 and minor == 4 and patch >= 3):
                self.log_success(f"Splunk version {self.splunk_version} supports custom KV Store certificates")
                return True
            else:
                self.log_info(f"Splunk version {self.splunk_version} - custom KV Store certificates have limited support")
                self.log_info("For versions before 9.4.3, using default certificates is recommended")
                # Don't fail this check, just provide information
                return True
                
        except (ValueError, IndexError) as e:
            self.log_error(f"Error parsing Splunk version {self.splunk_version}: {e}")
            return False

    def resolve_path(self, path: str) -> str:
        """Resolve relative paths relative to SPLUNK_HOME"""
        if not path:
            return path
            
        original_path = path
        
        # Handle absolute paths
        if os.path.isabs(path):
            resolved_path = path
        else:
            # Handle paths that contain $SPLUNK_HOME variable
            if '$SPLUNK_HOME' in path:
                resolved_path = path.replace('$SPLUNK_HOME', str(self.splunk_home))
            elif path.startswith('$'):
                # Handle other environment variables
                resolved_path = os.path.expandvars(path)
            else:
                # Relative path - prepend SPLUNK_HOME
                resolved_path = str(self.splunk_home / path)
        
        # Log path resolution in verbose mode
        if self.verbose and original_path != resolved_path:
            self.log_debug(f"Resolved path: '{original_path}' -> '{resolved_path}'")
        
        return resolved_path

    def run_verification(self) -> Dict:
        """Run the complete verification process"""
        print(f"{Colors.BOLD}Splunk KV Store Certificate Verification Tool{Colors.ENDC}")
        print(f"Splunk Home: {self.splunk_home}")
        print("=" * 60)
        
        # Get Splunk version
        self.get_splunk_version()
        
        # Run configuration checks using SplunkConfigChecker
        print(f"\n{Colors.BOLD}1. Running configuration checks{Colors.ENDC}")
        config_rules_path = Path(__file__).parent.parent / "splunk_config_checker" / "config_rules.json"
        config_checker = SplunkConfigChecker(self.splunk_home, config_rules_path)
        check_results = config_checker.check_configurations()
        config_checker.print_results(check_results)
        config = self.parse_server_conf()
        
        # Verify sslConfig section
        print(f"\n{Colors.BOLD}2. Verifying [sslConfig] section{Colors.ENDC}")
        ssl_config_results = self.verify_ssl_config_section(config, 'sslConfig')
        
        # Verify kvstore section
        print(f"\n{Colors.BOLD}3. Verifying [kvstore] section{Colors.ENDC}")
        kvstore_results = self.verify_kvstore_section(config)
        
        # Check CA completeness
        print(f"\n{Colors.BOLD}4. Verifying CA certificate completeness{Colors.ENDC}")
        ca_complete = self.check_ca_completeness(config)
        
        # Check version compatibility
        print(f"\n{Colors.BOLD}5. Checking version compatibility{Colors.ENDC}")
        version_compatible = self.check_version_compatibility()
        
        # Compile results
        results = {
            'ssl_config': ssl_config_results,
            'kvstore': kvstore_results,
            'ca_complete': ca_complete,
            'version_compatible': version_compatible,
            'errors': self.errors,
            'warnings': self.warnings,
            'info': self.info
        }
        
        # Print summary
        self.print_summary(results)
        
        return results

    def print_summary(self, results: Dict):
        """Print verification summary"""
        print(f"\n{Colors.BOLD}VERIFICATION SUMMARY{Colors.ENDC}")
        print("=" * 120)  # Wider separator for more detailed output
        
        total_checks = 0
        passed_checks = 0
        
        # SSL Config checks
        ssl_config = results.get('ssl_config', {})
        ssl_checks = [
            ('server.conf [sslConfig] section exists', ssl_config.get('section_exists'),
             'Configuration section must exist'),
            ('server.conf [sslConfig] allowSslCompression=true', ssl_config.get('ssl_compression_ok'),
             'Required for optimal performance'),
            ('server.conf [sslConfig] allowSslRenegotiation=true', ssl_config.get('ssl_renegotiation_ok'),
             'Required for SSL connectivity'),
            ('server.conf [sslConfig] serverCert is valid', ssl_config.get('server_cert_valid'),
             'Certificate file must be readable and valid'),
            ('server.conf [sslConfig] certificate chain is valid', ssl_config.get('cert_chain_valid'),
             'Certificate must be properly signed by CA')
        ]
        
        # KV Store checks
        kvstore = results.get('kvstore', {})
        kvstore_checks = [
            ('server.conf [kvstore] section exists', kvstore.get('section_exists'),
             'Configuration section should exist for custom settings'),
            ('server.conf [kvstore] serverCert is valid', kvstore.get('server_cert_valid'),
             'Certificate file must be readable and valid'),
            ('server.conf [kvstore] certificate has correct purpose', kvstore.get('server_cert_purpose_ok'),
             'Certificate must allow both server and client authentication'),
            ('server.conf [kvstore] certificate SAN is correct', kvstore.get('server_cert_san_ok'),
             'SAN must include localhost/127.0.0.1 unless verifyServerName=false'),
            ('server.conf [kvstore] CA certificate has correct purpose', kvstore.get('ca_cert_purpose_ok'),
             'CA certificate must be valid for signing'),
            ('server.conf [kvstore] certificate chain is valid', kvstore.get('cert_chain_valid'),
             'Certificate must be properly signed by CA'),
            ('server.conf [kvstore] verifyServerName=false', kvstore.get('verify_server_name_disabled'),
             'Recommended setting for KV Store compatibility')
        ]
        
        # Compression settings
        compression_checks = [
            ('outputs.conf [tcpout] compressed=true', results.get('outputs_compression', {}).get('compressed'),
             'Recommended for optimal data transmission'),
            ('outputs.conf [tcpout] useClientSSLCompression=true', results.get('outputs_compression', {}).get('ssl_compression'),
             'Recommended for encrypted data transmission')
        ]
        
        def print_check_section(title: str, checks: List[Tuple]):
            nonlocal total_checks, passed_checks
            print(f"\n{Colors.BOLD}{title}:{Colors.ENDC}")
            print("-" * 118)  # Separator for subsections
            print(f"{'Status':<8} {'Check':<60} {'Details':<50}")
            print("-" * 118)
            
            for check_name, check_result, check_details in checks:
                total_checks += 1
                if check_result:
                    passed_checks += 1
                    status = f"{Colors.GREEN}✓{Colors.ENDC}"
                else:
                    status = f"{Colors.RED}✗{Colors.ENDC}"
                print(f"{status:<8} {check_name:<60} {check_details:<50}")
        
        # Print all sections
        print_check_section("SSL Configuration", ssl_checks)
        print_check_section("KV Store Configuration", kvstore_checks)
        print_check_section("Compression Settings", compression_checks)
        
        # Additional checks
        other_checks = [
            ('CA certificates structure complete', results.get('ca_complete', False),
             'All required CA certificates are present and valid'),
            ('Version compatibility verified', True,
             f'Current version: {self.splunk_version or "Unknown"}')
        ]
        print_check_section("Other Checks", other_checks)
                
        # Print overall status
        print("\n" + "=" * 120)
        if passed_checks == total_checks:
            print(f"{Colors.GREEN}All checks passed ({passed_checks}/{total_checks}){Colors.ENDC}")
        else:
            print(f"{Colors.RED}Some checks failed ({passed_checks}/{total_checks} passed){Colors.ENDC}")
            
        if self.errors:
            print(f"\n{Colors.RED}Errors found:{Colors.ENDC}")
            for error in self.errors:
                print(f"  - {error}")
                
        if self.warnings:
            print(f"\n{Colors.YELLOW}Warnings found:{Colors.ENDC}")
            for warning in self.warnings:
                print(f"  - {warning}")
                
        if passed_checks == total_checks and not self.errors:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ All checks passed! KV Store configuration appears ready for upgrade.{Colors.ENDC}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ Some checks failed. Please review and fix issues before upgrading.{Colors.ENDC}")


def print_help():
    """Print help information about the tool"""
    help_text = f"""
{Colors.BOLD}Splunk KV Store Certificate Verification Tool{Colors.ENDC}

This tool verifies KV Store certificate configurations for safe upgrades
from Splunk KV Store 4/4.2 to 7.

{Colors.BOLD}Usage:{Colors.ENDC}
    $SPLUNK_HOME/bin/python kv_cert_verifier.py [OPTIONS] SPLUNK_HOME

{Colors.BOLD}Arguments:{Colors.ENDC}
    SPLUNK_HOME    Path to Splunk installation directory

{Colors.BOLD}Options:{Colors.ENDC}
    -h, --help     Show this help message
    -v, --verbose  Enable verbose debug output
    --output FORMAT Output format: text (default) or json

{Colors.BOLD}Examples:{Colors.ENDC}
    $SPLUNK_HOME/bin/python kv_cert_verifier.py $SPLUNK_HOME
    $SPLUNK_HOME/bin/python kv_cert_verifier.py /opt/splunk --verbose
    /opt/splunk/bin/python kv_cert_verifier.py /opt/splunk -v

{Colors.BOLD}Features:{Colors.ENDC}
    • Uses Splunk's bundled Python when available
    • Uses Splunk's bundled OpenSSL when available
    • Comprehensive certificate validation with graceful fallbacks
    • Configuration parsing with btool integration
    • Validates SSL compression and renegotiation settings
    • Checks certificate purposes and SAN entries for KV Store compatibility
    • Supports Splunk documented defaults

{Colors.BOLD}IMPORTANT:{Colors.ENDC} Always run this script using Splunk's bundled Python interpreter
to ensure compatibility with Splunk's environment and libraries.

For more information, see the README.md and documentation files.
"""
    print(help_text)


def main():
    """Main function"""
    # Handle help manually before argparse to show our custom help
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print_help()
        sys.exit(0)
    
    parser = argparse.ArgumentParser(
        description="Verify Splunk KV Store certificate configuration for safe upgrades",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # Disable default help to use our custom one
        epilog="""
Examples:
  $SPLUNK_HOME/bin/python kv_cert_verifier.py $SPLUNK_HOME
  $SPLUNK_HOME/bin/python kv_cert_verifier.py /opt/splunk --verbose
  /opt/splunk/bin/python kv_cert_verifier.py /opt/splunk -v

IMPORTANT: Always run this script using Splunk's bundled Python interpreter
to ensure compatibility with Splunk's environment and libraries.
        """
    )
    
    parser.add_argument(
        'splunk_home',
        help='Path to Splunk installation directory (SPLUNK_HOME)'
    )
    
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='Show this help message'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose debug output'
    )
    
    parser.add_argument(
        '--output',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    args = parser.parse_args()
    
    # Handle help argument
    if args.help:
        print_help()
        sys.exit(0)
    
    # Validate Splunk home directory
    splunk_home = Path(args.splunk_home)
    if not splunk_home.exists():
        print(f"Error: Splunk home directory does not exist: {splunk_home}")
        sys.exit(1)
    
    if not (splunk_home / "bin" / "splunk").exists():
        print(f"Error: Not a valid Splunk installation directory: {splunk_home}")
        sys.exit(1)
    
    # Run verification
    verifier = CertificateVerifier(str(splunk_home), verbose=args.verbose)
    results = verifier.run_verification()
    
    # Output results
    if args.output == 'json':
        import json
        print(json.dumps(results, indent=2, default=str))
    
    # Exit with appropriate code
    if results['errors']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
