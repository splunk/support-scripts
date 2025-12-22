#!/opt/splunk/bin/python
"""
Splunk Configuration Checker

A generic configuration checker for Splunk configurations that can verify settings
across different conf files using rules defined in JSON.

Usage:
    from splunk_config_checker import SplunkConfigChecker
    checker = SplunkConfigChecker(splunk_home, rules_file)
    results = checker.check_configurations()

Author: Splunk Configuration Checker
Version: 1.0
"""

import os
import sys
import json
import configparser
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

class Colors:
    """ANSI color codes for terminal output"""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"

class CheckLevel(Enum):
    """Severity levels for configuration checks"""
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"

@dataclass
class ConfigRule:
    """Represents a configuration validation rule"""
    filename: str
    stanza: str
    setting: str
    expected_value: Any
    level: CheckLevel
    message: Optional[str] = None

@dataclass
class CheckResult:
    """Represents the result of a configuration check"""
    rule: ConfigRule
    actual_value: Optional[str]
    passed: bool
    message: str

class SplunkConfigChecker:
    """Generic Splunk configuration checker"""
    
    def __init__(self, splunk_home: Path, rules_file: Path):
        """Initialize the checker with Splunk home path and rules file path"""
        self.splunk_home = Path(splunk_home)
        self.rules_file = Path(rules_file)
        self.rules: List[ConfigRule] = []
        self._load_rules()
        
    def _load_rules(self) -> None:
        """Load configuration rules from JSON file"""
        try:
            with open(self.rules_file) as f:
                rules_data = json.load(f)
                
            for rule in rules_data["rules"]:
                self.rules.append(ConfigRule(
                    filename=rule["filename"],
                    stanza=rule["stanza"],
                    setting=rule["setting"],
                    expected_value=rule["expected_value"],
                    level=CheckLevel(rule.get("level", "WARN").upper()),
                    message=rule.get("message")
                ))
                
        except Exception as e:
            print(f"Error loading rules file: {e}", file=sys.stderr)
            sys.exit(1)

    def get_btool_config(self, conf_name: str) -> Dict:
        """Get configuration using splunk btool"""
        try:
            btool_cmd = [
                os.path.join(str(self.splunk_home), 'bin', 'splunk'),
                'btool',
                conf_name,
                'list',
                #'--no-default',
                #'--debug'
            ]
            
            btool_output = subprocess.check_output(btool_cmd, text=True)
            return self._parse_btool_output(btool_output)
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to run btool for {conf_name}: {e}", file=sys.stderr)
            return self._parse_conf_manual(conf_name)

    def _parse_btool_output(self, output: str) -> Dict:
        """Parse btool output into a dictionary"""
        config = {}
        current_stanza = None
        
        for line in output.splitlines():
            line = line.strip()
            
            if line.startswith('[') and line.endswith(']'):
                current_stanza = line[1:-1]
                if current_stanza not in config:
                    config[current_stanza] = {}
            elif '=' in line and current_stanza is not None:
                key, value = line.split('=', 1)
                config[current_stanza][key.strip()] = value.strip()
                
        return config

    def _parse_conf_manual(self, conf_name: str) -> Dict:
        """Manual fallback parsing of configuration files"""
        config = configparser.ConfigParser(allow_no_value=True)
        config.optionxform = str  # Preserve case
        
        # List of paths to check (in precedence order: system/default, then system/local, then apps)
        conf_paths = []
        files_read = []

        # System default
        system_default = self.splunk_home / "etc" / "system" / "default" / f"{conf_name}.conf"
        if system_default.exists():
            conf_paths.append(system_default)

        # System local
        system_local = self.splunk_home / "etc" / "system" / "local" / f"{conf_name}.conf"
        if system_local.exists():
            conf_paths.append(system_local)

        # Apps directories (check common app locations)
        apps_dir = self.splunk_home / "etc" / "apps"
        if apps_dir.exists():
            for app_dir in apps_dir.iterdir():
                if app_dir.is_dir():
                    for subdir in ["default", "local"]:
                        app_conf = app_dir / subdir / f"{conf_name}.conf"
                        if app_conf.exists():
                            conf_paths.append(app_conf)

        # Read all configuration files (later files override earlier ones)
        for conf_path in conf_paths:
            try:
                config.read(conf_path)
                files_read.append(str(conf_path))
            except Exception as e:
                print(f"Error reading {conf_path}: {e}", file=sys.stderr)

        if not files_read:
            print(f"No {conf_name}.conf files found in {self.splunk_home}/etc/", file=sys.stderr)
                    
        result = {}
        for section in config.sections():
            result[section] = dict(config.items(section))
            
        return result

    def check_configurations(self) -> List[CheckResult]:
        """Check all configuration rules and return results"""
        results = []
        configs_cache = {}  # Cache configurations to avoid re-reading
        
        for rule in self.rules:
            # Get configuration, using cache if available
            if rule.filename not in configs_cache:
                configs_cache[rule.filename] = self.get_btool_config(rule.filename)
            config = configs_cache[rule.filename]
            
            # Check if stanza exists and get value
            actual_value = None
            if rule.stanza in config:
                actual_value = config[rule.stanza].get(rule.setting)
                
            # Special handling for "tcpout::" stanzas in outputs.conf
            if (not actual_value and rule.filename == "outputs" and
                rule.stanza.startswith("tcpout::") and "tcpout" in config):
                # Check parent tcpout stanza for inherited values
                actual_value = config["tcpout"].get(rule.setting)
            
            # Compare values
            passed = False
            if actual_value is not None:
                if isinstance(rule.expected_value, bool):
                    # Boolean comparison
                    actual_bool = str(actual_value).lower() in ('true', '1', 'yes', 'on')
                    passed = actual_bool == rule.expected_value
                elif isinstance(rule.expected_value, int):
                    # Integer comparison
                    try:
                        passed = int(actual_value) == rule.expected_value
                    except (ValueError, TypeError):
                        passed = False
                else:
                    # String comparison
                    passed = str(actual_value).strip() == str(rule.expected_value).strip()
                    
            # Generate message
            #print(f"Debug: Checking {rule.filename}.conf [{rule.stanza}] {rule.setting}: expected='{rule.expected_value}' ({type(rule.expected_value).__name__}), actual='{actual_value}' ({type(actual_value).__name__ if actual_value is not None else 'None'}), passed={passed}", file=sys.stderr)

            # Generate message
            if not passed:
                message = rule.message or (
                    f"Configuration {rule.setting} in [{rule.stanza}] of {rule.filename}.conf "
                    f"is not set to '{rule.expected_value}'. Current value: "
                    f"{actual_value if actual_value is not None else 'not set'}"
                )
            else:
                message = (
                    f"Configuration {rule.setting} in [{rule.stanza}] of {rule.filename}.conf "
                    f"is correctly set to '{rule.expected_value}'"
                )
                
            results.append(CheckResult(
                rule=rule,
                actual_value=actual_value,
                passed=passed,
                message=message
            ))
            
        return results

    def print_results(self, results: List[CheckResult]) -> None:
        """Print check results in a formatted way"""
        for result in results:
            level_str = result.rule.level.value
            if result.passed:
                print(f"{Colors.GREEN}[INFO] {result.message}{Colors.ENDC}")

            else:
                print(f"{Colors.RED}[{level_str}] {result.message}{Colors.ENDC}")

if __name__ == "__main__":

    splunk_home = Path("/opt/splunk")
    rules_file = Path("config_rules.json")

    checker = SplunkConfigChecker(splunk_home, rules_file)
    results = checker.check_configurations()
    checker.print_results(results)