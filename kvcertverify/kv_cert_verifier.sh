#!/bin/bash

# Splunk KV Store Certificate Verifier Script
# Companion script for comprehensive certificate verification before KV Store upgrades
# 
# This script provides both basic shell-based checks and comprehensive Python    if [[ -f "$server_conf" ]]; then
        local ssl_errors=0
        
        # Check for required sections
        if grep -q "^\[sslConfig\]" "$server_conf"; then
            print_success "sslConfig section found in local server.conf"
            # Check SSL settings in sslConfig section
            check_ssl_settings "$server_conf" "sslConfig"
            ssl_errors=$((ssl_errors + $?))
        else
            print_warning "sslConfig section not found in local server.conf"
            ssl_errors=$((ssl_errors + 1))
        fi
        
        if grep -q "^\[kvstore\]" "$server_conf"; then
            print_success "kvstore section found in local server.conf"
            # Check SSL settings in kvstore section
            check_ssl_settings "$server_conf" "kvstore"
            ssl_errors=$((ssl_errors + $?))
        else
            print_debug "kvstore section not found in local server.conf (may use defaults)"
        fi
        
        if [ $ssl_errors -gt 0 ]; then
            print_warning "Found $ssl_errors SSL configuration issues that may affect KV Store operation"
        fi
    else
        print_warning "Local server.conf not found: $server_conf"
    fiation using the kv_cert_verifier.py tool.
#
# Features:
# - Uses Splunk's bundled Python interpreter when available
# - Uses Splunk's bundled OpenSSL when available
# - Falls back gracefully to system tools if Splunk's bundled tools unavailable
# - Comprehensive certificate chain validation
# - Configuration parsing with btool integration
# - Supports Splunk documented defaults
#
# Version: 1.0

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
SPLUNK_HOME=""
VERBOSE=false
CHECK_ONLY=false

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_error() {
    print_status "$RED" "ERROR: $1"
}

print_success() {
    print_status "$GREEN" "SUCCESS: $1"
}

print_warning() {
    print_status "$YELLOW" "WARNING: $1"
}

print_info() {
    print_status "$BLUE" "INFO: $1"
}

print_debug() {
    if $VERBOSE; then
        print_status "$CYAN" "DEBUG: $1"
    fi
}

# Function to show usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] SPLUNK_HOME

Splunk KV Store Certificate Verifier Script

This script verifies KV Store certificate configurations for safe upgrades
from KV Store 4/4.2 to 7. It performs comprehensive validation of SSL
certificates and configuration settings.

Arguments:
    SPLUNK_HOME    Path to Splunk installation directory

Options:
    -h, --help     Show this help message
    -v, --verbose  Enable verbose output
    -c, --check    Only run basic checks (don't require Python dependencies)

Examples:
    $0 /opt/splunk
    $0 --verbose /opt/splunk
    $0 --check /opt/splunk

Features:
    • Uses Splunk's bundled Python when available
    • Uses Splunk's bundled OpenSSL when available
    • Comprehensive certificate validation with graceful fallbacks
    • Configuration parsing with btool integration
    • Validates SSL compression and renegotiation settings
    • Checks certificate purposes and SAN entries for KV Store compatibility
    • Supports Splunk documented defaults

For more information, see the README.md and documentation files.

EOF
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run OpenSSL command using Splunk's bundled OpenSSL
run_openssl_command() {
    local cmd_args=("$@")
    
    # Try Splunk's bundled OpenSSL first
    if [[ -f "$SPLUNK_HOME/bin/splunk" ]]; then
        "$SPLUNK_HOME/bin/splunk" cmd openssl "${cmd_args[@]}" 2>/dev/null
    else
        # Fallback to system OpenSSL
        openssl "${cmd_args[@]}" 2>/dev/null
    fi
}

# Function to check basic requirements
check_requirements() {
    local errors=0
    
    print_info "Checking basic requirements..."
    
    # Check if Splunk's bundled OpenSSL or system OpenSSL is available
    if [[ -f "$SPLUNK_HOME/bin/splunk" ]]; then
        if "$SPLUNK_HOME/bin/splunk" cmd openssl version >/dev/null 2>&1; then
            local openssl_version=$("$SPLUNK_HOME/bin/splunk" cmd openssl version 2>/dev/null)
            print_success "Splunk's bundled OpenSSL found: $openssl_version"
        else
            print_warning "Splunk's bundled OpenSSL not working, checking system OpenSSL"
            if command_exists openssl; then
                print_success "System OpenSSL found: $(openssl version)"
            else
                print_error "Neither Splunk's bundled nor system OpenSSL found - required for certificate analysis"
                errors=$((errors + 1))
            fi
        fi
    elif command_exists openssl; then
        print_success "System OpenSSL found: $(openssl version)"
    else
        print_error "OpenSSL not found - required for certificate analysis"
        errors=$((errors + 1))
    fi
    
    # Check if Python is available (for full script)
    if ! $CHECK_ONLY; then
        if command_exists python3; then
            print_success "Python 3 found: $(python3 --version)"
        elif command_exists python; then
            print_success "Python found: $(python --version)"
        else
            print_error "Python not found - required for full verification"
            errors=$((errors + 1))
        fi
    fi
    
    return $errors
}

# Function to validate Splunk home
validate_splunk_home() {
    if [[ ! -d "$SPLUNK_HOME" ]]; then
        print_error "Splunk home directory does not exist: $SPLUNK_HOME"
        return 1
    fi
    
    if [[ ! -f "$SPLUNK_HOME/bin/splunk" ]]; then
        print_error "Not a valid Splunk installation: $SPLUNK_HOME"
        return 1
    fi
    
    print_success "Valid Splunk installation found at: $SPLUNK_HOME"
    return 0
}

# Function to get Splunk version
get_splunk_version() {
    local version_file="$SPLUNK_HOME/etc/splunk.version"
    
    if [[ -f "$version_file" ]]; then
        local version=$(grep "^VERSION=" "$version_file" | cut -d'=' -f2)
        print_debug "Splunk version: $version"
        echo "$version"
    else
        print_warning "Could not determine Splunk version"
        echo "unknown"
    fi
}

# Function to check SSL settings in server.conf
check_ssl_settings() {
    local conf_file="$1"
    local section="$2"
    local setting_errors=0
    
    print_info "Checking SSL settings in $section..."
    
    # Check SSL compression setting
    if grep -A5 "^\[$section\]" "$conf_file" | grep -q "^allowSslCompression\s*=\s*true"; then
        print_success "SSL compression is enabled in $section"
    else
        print_error "SSL compression is not enabled in $section (allowSslCompression=true required)"
        setting_errors=$((setting_errors + 1))
    fi
    
    # Check SSL renegotiation setting
    if grep -A5 "^\[$section\]" "$conf_file" | grep -q "^allowSslRenegotiation\s*=\s*true"; then
        print_success "SSL renegotiation is enabled in $section"
    else
        print_error "SSL renegotiation is not enabled in $section (allowSslRenegotiation=true required)"
        setting_errors=$((setting_errors + 1))
    fi
    
    return $setting_errors
}

# Function to check server.conf exists and basic structure
check_server_conf() {
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    local default_conf="$SPLUNK_HOME/etc/system/default/server.conf"
    
    print_info "Checking server.conf files..."
    
    if [[ -f "$server_conf" ]]; then
        print_success "Local server.conf found: $server_conf"
        
        # Check for required sections
        if grep -q "^\[sslConfig\]" "$server_conf"; then
            print_success "sslConfig section found in local server.conf"
        else
            print_warning "sslConfig section not found in local server.conf"
        fi
        
        if grep -q "^\[kvstore\]" "$server_conf"; then
            print_success "kvstore section found in local server.conf"
        else
            print_debug "kvstore section not found in local server.conf (may use defaults)"
        fi
    else
        print_warning "Local server.conf not found: $server_conf"
    fi
    
    if [[ -f "$default_conf" ]]; then
        print_success "Default server.conf found: $default_conf"
    else
        print_error "Default server.conf not found: $default_conf"
        return 1
    fi
    
    return 0
}

# Function to check certificate purpose using OpenSSL
check_certificate_purpose() {
    local cert_file="$1"
    local is_ca=false
    local has_server_auth=false
    local has_client_auth=false
    local has_any_purpose=false
    
    # Get certificate purposes using OpenSSL
    local purposes
    if purposes=$(run_openssl_command x509 -in "$cert_file" -noout -purpose 2>/dev/null); then
        # Check for CA capabilities
        if echo "$purposes" | grep -q "CA:TRUE"; then
            is_ca=true
        fi
        
        # Check for server/client authentication
        if echo "$purposes" | grep -q "SSL server : Yes"; then
            has_server_auth=true
            has_any_purpose=true
        fi
        if echo "$purposes" | grep -q "SSL client : Yes"; then
            has_client_auth=true
            has_any_purpose=true
        fi
        
        # Output results
        if ! $has_any_purpose; then
            print_success "Certificate has no purpose restrictions (suitable for any use)"
            return 0
        fi
        
        if $has_server_auth && $has_client_auth; then
            print_success "Certificate has both server and client authentication purposes"
            return 0
        elif $has_server_auth; then
            print_warning "Certificate only has server authentication purpose"
            return 1
        elif $has_client_auth; then
            print_warning "Certificate only has client authentication purpose"
            return 1
        fi
    else
        print_warning "Could not determine certificate purposes"
        return 0  # Be lenient if we can't check
    fi
    
    return 1
}

# Function to analyze certificate file
analyze_certificate() {
    local cert_file="$1"
    local cert_name="$2"
    
    if [[ ! -f "$cert_file" ]]; then
        print_error "$cert_name certificate file not found: $cert_file"
        return 1
    fi
    
    print_info "Analyzing $cert_name certificate: $cert_file"
    
    # Check if file is readable
    if [[ ! -r "$cert_file" ]]; then
        print_error "$cert_name certificate file is not readable: $cert_file"
        return 1
    fi
    
    # Basic file format check
    if file "$cert_file" | grep -q "PEM certificate"; then
        print_success "$cert_name certificate appears to be in PEM format"
    elif file "$cert_file" | grep -q "ASCII text"; then
        if grep -q "BEGIN CERTIFICATE" "$cert_file"; then
            print_success "$cert_name certificate appears to be in PEM format"
        else
            print_warning "$cert_name certificate format unclear"
        fi
    else
        print_warning "$cert_name certificate may be in binary format (DER/PKCS12)"
    fi
    
    # Try to extract certificate info with OpenSSL (prefer Splunk's bundled version)
    local openssl_available=false
    
    # Check if we can use OpenSSL (Splunk's bundled or system)
    if [[ -f "$SPLUNK_HOME/bin/splunk" ]] && "$SPLUNK_HOME/bin/splunk" cmd openssl version >/dev/null 2>&1; then
        openssl_available=true
        print_debug "Using Splunk's bundled OpenSSL for certificate analysis"
    elif command_exists openssl; then
        openssl_available=true
        print_debug "Using system OpenSSL for certificate analysis"
    fi
    
    if $openssl_available; then
        print_info "Certificate details for $cert_name:"
        
        # Try PEM format first
        if run_openssl_command x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
            # Get subject
            local subject=$(run_openssl_command x509 -in "$cert_file" -noout -subject | sed 's/subject=//')
            print_debug "  Subject: $subject"
            
            # Get issuer
            local issuer=$(run_openssl_command x509 -in "$cert_file" -noout -issuer | sed 's/issuer=//')
            print_debug "  Issuer: $issuer"
            
            # Get validity dates
            local not_before=$(run_openssl_command x509 -in "$cert_file" -noout -startdate | sed 's/notBefore=//')
            local not_after=$(run_openssl_command x509 -in "$cert_file" -noout -enddate | sed 's/notAfter=//')
            print_debug "  Valid from: $not_before"
            print_debug "  Valid until: $not_after"
            
            # Check if expired
            if run_openssl_command x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
                print_success "  Certificate is currently valid"
            else
                print_error "  Certificate has expired!"
            fi
            
            # Check SAN
            local san=$(run_openssl_command x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3 Subject Alternative Name:")
            if [[ -n "$san" ]]; then
                print_debug "  Subject Alternative Names: $san"
                if echo "$san" | grep -q "127.0.0.1\|localhost"; then
                    print_success "  SAN contains localhost/127.0.0.1"
                else
                    print_warning "  SAN does not contain localhost/127.0.0.1"
                fi
            else
                print_debug "  No Subject Alternative Names found"
            fi
            
        else
            print_warning "Could not parse $cert_name certificate with OpenSSL (may be DER format or encrypted)"
        fi
        
        # Check certificate purposes
        print_info "Checking certificate purposes..."
        check_certificate_purpose "$cert_file"
    fi
    
    return 0
}

# Function to check CA certificate completeness
check_ca_completeness() {
    local cert_dir="$1"
    local ca_errors=0
    
    if [[ ! -d "$cert_dir" ]]; then
        print_error "CA directory not found: $cert_dir"
        return 1
    fi
    
    print_info "Checking CA certificates in: $cert_dir"
    
    # Count CA certificates
    local ca_count=0
    while IFS= read -r -d '' ca_file; do
        if run_openssl_command x509 -in "$ca_file" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
            ca_count=$((ca_count + 1))
            print_debug "Found CA certificate: $ca_file"
        fi
    done < <(find "$cert_dir" -type f -name "*.pem" -o -name "*.crt" -print0)
    
    if [ $ca_count -eq 0 ]; then
        print_error "No CA certificates found in $cert_dir"
        ca_errors=$((ca_errors + 1))
    else
        print_success "Found $ca_count CA certificate(s) in $cert_dir"
    fi
    
    return $ca_errors
}

# Function to extract certificate paths from server.conf
extract_cert_paths() {
    local server_conf="$1"
    local section="$2"
    
    if [[ ! -f "$server_conf" ]]; then
        return 1
    fi
    
    # Extract certificate paths from specified section
    awk -v section="[$section]" '
    $0 == section { in_section = 1; next }
    /^\[/ && in_section { in_section = 0 }
    in_section && /^(serverCert|caCertFile|sslRootCAPath)/ {
        split($0, arr, "=")
        if (length(arr) >= 2) {
            key = arr[1]
            gsub(/^[ \t]+|[ \t]+$/, "", key)  # trim whitespace
            value = arr[2]
            gsub(/^[ \t]+|[ \t]+$/, "", value)  # trim whitespace
            print key "=" value
        }
    }' "$server_conf"
}

# Function to display validation mode warning
show_validation_warning() {
    cat << EOF

${YELLOW}=== VALIDATION MODE WARNING ===${NC}
This script is running in basic validation mode, which provides a subset of the full
validation capabilities available in the Python version. For the most comprehensive
validation, please use the Python script (kv_cert_verifier.py) which includes:

- More thorough certificate chain validation
- Complete certificate purpose validation
- Detailed CA validation and completeness checks
- Enhanced configuration validation
- JSON output format support
- Splunk version compatibility checks

To use the Python version:
$SPLUNK_HOME/bin/python kv_cert_verifier.py $SPLUNK_HOME

EOF
}

# Function to run basic certificate checks
run_basic_checks() {
    show_validation_warning
    print_info "Running basic certificate checks..."
    
    local server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
    
    if [[ -f "$server_conf" ]]; then
        # Check sslConfig section
        print_info "Checking sslConfig certificates..."
        while IFS='=' read -r key value; do
            if [[ "$key" == "serverCert" || "$key" == "caCertFile" || "$key" == "sslRootCAPath" ]]; then
                # Resolve relative paths
                if [[ "$value" =~ ^/ ]]; then
                    cert_path="$value"
                else
                    cert_path="$SPLUNK_HOME/$value"
                fi
                analyze_certificate "$cert_path" "sslConfig.$key"
                
                # Check CA directory if this is sslRootCAPath
                if [[ "$key" == "sslRootCAPath" && -d "$cert_path" ]]; then
                    check_ca_completeness "$cert_path"
                fi
            fi
        done < <(extract_cert_paths "$server_conf" "sslConfig")
        
        # Check kvstore section
        print_info "Checking kvstore certificates..."
        while IFS='=' read -r key value; do
            if [[ "$key" == "serverCert" || "$key" == "caCertFile" || "$key" == "sslRootCAPath" ]]; then
                # Resolve relative paths
                if [[ "$value" =~ ^/ ]]; then
                    cert_path="$value"
                else
                    cert_path="$SPLUNK_HOME/$value"
                fi
                analyze_certificate "$cert_path" "kvstore.$key"
            fi
        done < <(extract_cert_paths "$server_conf" "kvstore")
    fi
}

# Function to run Python verification script
run_python_verification() {
    local script_dir="$(dirname "$0")"
    local python_script="$script_dir/kv_cert_verifier.py"
    
    if [[ ! -f "$python_script" ]]; then
        print_error "Python verification script not found: $python_script"
        return 1
    fi
    
    print_info "Running comprehensive Python verification..."
    
    # Try different Python interpreters with SSL library compatibility checks
    local python_cmd=""
    local python_worked=false
    
    # Test function to check if Python interpreter works with SSL libraries
    test_python_ssl() {
        local test_python="$1"
        print_debug "Testing Python interpreter: $test_python"
        
        # Test basic Python functionality
        if ! $test_python --version >/dev/null 2>&1; then
            print_warning "Python interpreter $test_python failed basic version check"
            return 1
        fi
        
        # Test SSL library loading (common cause of libssl.so.1.0.0 errors)
        if ! $test_python -c "import ssl; print('SSL module loaded successfully')" >/dev/null 2>&1; then
            print_warning "Python interpreter $test_python failed SSL module test"
            return 1
        fi
        
        # Test subprocess module (needed for btool commands)
        if ! $test_python -c "import subprocess; print('subprocess module loaded successfully')" >/dev/null 2>&1; then
            print_warning "Python interpreter $test_python failed subprocess module test"
            return 1
        fi
        
        print_success "Python interpreter $test_python passed compatibility tests"
        return 0
    }
    
    # Try Splunk's bundled Python first, but with SSL compatibility check
    if [[ -f "$SPLUNK_HOME/bin/python" ]]; then
        if test_python_ssl "$SPLUNK_HOME/bin/python"; then
            python_cmd="$SPLUNK_HOME/bin/python"
            python_worked=true
            print_debug "Using Splunk's bundled Python: $python_cmd"
        else
            print_warning "Splunk's bundled Python has SSL library compatibility issues, trying alternatives"
        fi
    else
        print_info "Splunk's bundled Python not found at $SPLUNK_HOME/bin/python"
    fi
    
    # Fall back to system Python 3 if Splunk Python didn't work
    if ! $python_worked && command_exists python3; then
        if test_python_ssl "python3"; then
            python_cmd="python3"
            python_worked=true
            print_info "Using system Python 3: $python_cmd"
        else
            print_warning "System Python 3 has compatibility issues"
        fi
    fi
    
    # Fall back to system Python if Python 3 didn't work
    if ! $python_worked && command_exists python; then
        if test_python_ssl "python"; then
            python_cmd="python"
            python_worked=true
            print_info "Using system Python: $python_cmd"
        else
            print_warning "System Python has compatibility issues"
        fi
    fi
    
    # If no Python interpreter worked, return error
    if ! $python_worked; then
        print_error "No compatible Python interpreter found"
        print_error "All Python interpreters failed SSL library or compatibility tests"
        print_info "This often happens when Splunk's Python has SSL library version conflicts"
        print_info "Consider running with --check flag for basic validation without Python dependencies"
        return 1
    fi
    
    # Check Python version for informational purposes
    local python_version=$($python_cmd --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    print_info "Python version: $python_version"
    
    # Run the Python script with enhanced error handling
    local python_args=""
    if $VERBOSE; then
        python_args="--verbose"
    fi
    
    print_info "Executing: $python_cmd $python_script $python_args $SPLUNK_HOME"
    
    # Run with comprehensive error handling and capture output
    local output
    local exit_code
    
    if output=$($python_cmd "$python_script" $python_args "$SPLUNK_HOME" 2>&1); then
        echo "$output"
        print_success "Python verification completed successfully"
        return 0
    else
        exit_code=$?
        echo "$output"
        
        # Analyze the error to provide helpful guidance
        if echo "$output" | grep -q "libssl\.so\.1\.0\.0"; then
            print_error "SSL library compatibility error detected"
            print_info "This is a common issue with Splunk's bundled Python and system SSL libraries"
            print_info "Try running with --check flag for basic validation without Python dependencies"
        elif echo "$output" | grep -q "No module named"; then
            print_error "Python module import error detected"
            print_info "Some Python dependencies may be missing"
        elif echo "$output" | grep -q "Permission denied"; then
            print_error "Permission error detected - check file permissions"
        else
            print_warning "Python verification encountered an error"
        fi
        
        print_info "Python verification exit code: $exit_code"
        return $exit_code
    fi
}

# Main function
main() {
    local script_name=$(basename "$0")
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--check)
                CHECK_ONLY=true
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$SPLUNK_HOME" ]]; then
                    SPLUNK_HOME="$1"
                else
                    print_error "Multiple Splunk home directories specified"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Check if Splunk home was provided
    if [[ -z "$SPLUNK_HOME" ]]; then
        print_error "Splunk home directory must be specified"
        usage
        exit 1
    fi
    
    # Print header
    echo "========================================"
    echo "Splunk KV Store Certificate Verifier"
    echo "========================================"
    echo
    
    # Run checks
    check_requirements || {
        print_error "Requirements check failed"
        exit 1
    }
    
    validate_splunk_home || {
        print_error "Splunk home validation failed"
        exit 1
    }
    
    get_splunk_version
    
    check_server_conf || {
        print_error "server.conf check failed"
        exit 1
    }
    
    if $CHECK_ONLY; then
        print_info "Running basic checks only..."
        run_basic_checks
    else
        print_info "Running comprehensive verification..."
        if ! run_python_verification; then
            local python_exit_code=$?
            if [[ $python_exit_code -eq 1 ]]; then
                print_warning "Python verification found issues, but completed successfully"
                print_info "Check the detailed output above for specific problems to address"
            else
                print_warning "Python verification failed, falling back to basic checks"
                print_info "This often happens due to SSL library compatibility issues with Splunk's Python"
                print_info "Running basic certificate validation instead..."
                echo
                run_basic_checks
                echo
                print_info "For comprehensive validation, consider:"
                print_info "  • Use --check flag for basic validation only"
                print_info "  • Install system Python 3 with SSL support"
                print_info "  • Check Splunk Python SSL library compatibility"
            fi
        fi
    fi
    
    echo
    print_info "Verification complete. Review output above for any issues."
}

# Run main function
main "$@"
