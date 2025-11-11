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
                '--no-default',
                '--debug'
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
        
        try:
            for line in output.splitlines():
                line = line.strip()
                
                if line.startswith('[') and line.endswith(']'):
                    current_stanza = line[1:-1]
                    if current_stanza not in config:
                        config[current_stanza] = {}
                elif '=' in line and current_stanza is not None:
                    key, value = line.split('=', 1)
                    config[current_stanza][key.strip()] = value.strip()
        except Exception as e:
            print(f"Error parsing btool output: {e}", file=sys.stderr)
            
        return config

    def _parse_conf_manual(self, conf_name: str) -> Dict:
        """Manual fallback parsing of configuration files"""
        conf_path_local = self.splunk_home / "etc" / "system" / "local" / f"{conf_name}.conf"
        conf_path_default = self.splunk_home / "etc" / "system" / "default" / f"{conf_name}.conf"
        
        config = configparser.ConfigParser(allow_no_value=True)
        config.optionxform = str  # Preserve case
        
        # Read default first, then local (local overrides default)
        for conf_path in [conf_path_default, conf_path_local]:
            if conf_path.exists():
                try:
                    config.read(conf_path)
                except Exception as e:
                    print(f"Error reading {conf_path}: {e}", file=sys.stderr)
                    
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
                    passed = str(actual_value).lower() == str(rule.expected_value).lower()
                else:
                    passed = str(actual_value) == str(rule.expected_value)
                    
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
                print(f"[PASS] {result.message}")
            else:
                print(f"[{level_str}] {result.message}")