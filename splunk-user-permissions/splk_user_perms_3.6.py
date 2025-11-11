import argparse
import subprocess
import re
import os
from fnmatch import fnmatch
import xml.etree.ElementTree as ET
import requests
import getpass
from functools import reduce

requests.packages.urllib3.disable_warnings()

class PermissionValue:
    """Stores metadata about a permission's source."""
    def __init__(self, source, filename, line):
        self.source, self.filename, self.line = source, filename, line

class User:
    """Represents a Splunk user with roles and detected conflicts."""
    def __init__(self, username):
        self.username = username
        self.roles = []  # List of Role objects
        self.index_conflicts = []  # Conflicting indexes across all roles
        self.capability_conflicts = []  # Conflicting capabilities across all roles

    def get_user_roles(self, splunk_host, session_key, verbose=0):
        """Fetch roles assigned to the user via Splunk REST API."""
        url = f"{splunk_host}/services/authentication/users/{self.username}?output_mode=json"
        if verbose >= 3:
            print(f"DEBUG: GET {url} with session_key={session_key[:10]}...")
        try:
            response = requests.get(url, headers={"Authorization": f"Splunk {session_key}"}, verify=False)
            response.raise_for_status()
            data = response.json()
            return data["entry"][0]["content"]["roles"] if data.get("entry") else []
        except (requests.RequestException, KeyError, IndexError) as e:
            if verbose >= 3 and isinstance(e, requests.RequestException) and 'response' in locals():
                print(f"DEBUG: Response content: {response.text}")
            raise Exception(f"Failed to retrieve user roles for {self.username}: {e}")

    def _detect_index_conflicts(self, enabled, disabled):
        """Identify index conflicts, including wildcards, using a list comprehension."""
        return [e for e in enabled for d in disabled if e == d or (d == "*" or fnmatch(e, d))]

    def _detect_capability_conflicts(self, capabilities):
        """Identify capability conflicts between enabled and disabled states."""
        enabled = {cap for cap in capabilities if "::disabled" not in cap}
        disabled = {cap.split("::")[0] for cap in capabilities if "::disabled" in cap}
        return enabled & disabled

    def populate_user(self, splunk_host, username, password, splunk_bin, verbose=0):
        """Populate user with role data and detect conflicts using btool."""
        if verbose >= 3:
            print(f"DEBUG: Authenticating to {splunk_host} as {username}...")
        session_key = get_session_key(splunk_host, username, password, verbose)
        if not session_key:
            raise Exception("Authentication failed: No session key returned.")

        user_roles = self.get_user_roles(splunk_host, session_key, verbose)
        if verbose >= 3:
            print(f"DEBUG: Fetched roles for {self.username}: {user_roles}")

        # Process roles recursively with a helper function
        def process_role(role_name, processed=None, is_inherited=False):
            processed = processed or set()
            if role_name in processed:
                return None
            processed.add(role_name)

            role = Role(role_name, is_inherited)
            perms = role.get_role_permissions_btool(splunk_bin, verbose, user_roles)
            if not perms:
                if verbose >= 3:
                    print(f"DEBUG: No permissions found for role {role_name}")
                return None

            if verbose >= 3:
                print(f"DEBUG: Permissions for {role_name}: {perms}")
            role.update_from_perms(perms, role_name)

            # Detect internal conflicts
            role.index_conflicts = self._detect_index_conflicts(
                role.allowed_indexes.keys(), role.disallowed_indexes.keys()
            )
            role.capability_conflicts = list(self._detect_capability_conflicts(role.capabilities.keys()))

            # Process inherited roles using lambda and filter
            role.inherited_roles = list(filter(None, map(
                lambda r: process_role(r, processed, True), perms["inherited"]
            )))
            if verbose >= 3:
                print(f"DEBUG: Role {role_name} inherited roles: {[r.name for r in role.inherited_roles]}")

            # Detect conflicts with inherited roles using reduce and dict union
            for inherited in role.inherited_roles:
                role.index_conflicts.extend(self._detect_index_conflicts(
                    role.allowed_indexes.keys(), inherited.disallowed_indexes.keys()
                ))
                role.index_conflicts.extend(self._detect_index_conflicts(
                    inherited.allowed_indexes.keys(), role.disallowed_indexes.keys()
                ))
                all_caps = reduce(lambda x, y: x | y, [role.capabilities.keys(), inherited.capabilities.keys()])
                role.capability_conflicts += list(self._detect_capability_conflicts(all_caps))

            if verbose >= 3:
                print(f"DEBUG: Role {role_name} index conflicts: {role.index_conflicts}")
                print(f"DEBUG: Role {role_name} capability conflicts: {role.capability_conflicts}")
            return role

        # Populate roles and extend with inherited roles
        self.roles = list(filter(None, map(process_role, user_roles)))
        self.roles.extend([r for role in self.roles for r in role.inherited_roles])

        # Aggregate user-level conflicts
        all_enabled_indexes = {idx for role in self.roles for idx in role.allowed_indexes}
        all_disabled_indexes = {idx for role in self.roles for idx in role.disallowed_indexes}
        all_caps = {cap for role in self.roles for cap in role.capabilities}
        self.index_conflicts = self._detect_index_conflicts(all_enabled_indexes, all_disabled_indexes)
        self.capability_conflicts = list(self._detect_capability_conflicts(all_caps))

        if verbose >= 3:
            print(f"DEBUG: User {self.username} - enabled indexes: {all_enabled_indexes}, "
                  f"disabled indexes: {all_disabled_indexes}, index conflicts: {self.index_conflicts}")
            print(f"DEBUG: User {self.username} - capabilities: {all_caps}, "
                  f"capability conflicts: {self.capability_conflicts}")

    def print_results(self, verbose=0):
        """Display user roles and conflicts in a formatted output."""
        if verbose:
            print(f"DISCLAIMER: Verbose mode (-{'v' * verbose}) "
                  f"{'filters out defaults' if verbose == 1 else 'includes all settings' + (' and debug info' if verbose >= 3 else '')}.")

        print(f"username: {self.username}")
        print("  index conflicts:")
        print("\n".join(f"    {c}" for c in sorted(set(self.index_conflicts))) or "    None")
        print("  capability conflicts:")
        print("\n".join(f"    {c}" for c in sorted(set(self.capability_conflicts))) or "    None")
        print("  roles:")

        # Use a dictionary to map attributes to their names for cleaner printing
        attr_map = {
            "capabilities": lambda r: r.capabilities,
            "allowed_indexes": lambda r: r.allowed_indexes,
            "disallowed_indexes": lambda r: r.disallowed_indexes,
            "misc": lambda r: r.misc
        }

        for role in sorted(self.roles, key=lambda r: r.name):
            prefix = "Inherited " if role.is_inherited else ""
            print(f"    {prefix}Role: {role.name}\n      name: {role.name}")
            for attr_name, attr_func in attr_map.items():
                print(f"      {attr_name}:")
                for key in sorted(attr_func(role).keys()):
                    print(f"        {key}")
                    if verbose:
                        perm = attr_func(role)[key]
                        print(f"          Source: {perm.source}\n          File: {perm.filename}\n          Line: {perm.line}")
            print(f"      inherited:\n        {', '.join(r.name for r in role.inherited_roles) or 'None'}")
            print("      index conflicts:")
            print("\n".join(f"        {c}" for c in sorted(set(role.index_conflicts))) or "        None")
            print("      capability conflicts:")
            print("\n".join(f"        {c}" for c in sorted(set(role.capability_conflicts))) or "        None")

class Role(User):
    """Represents a Splunk role with permissions and inherited roles."""
    def __init__(self, name, is_inherited=False):
        super().__init__(None)
        self.name = name
        self.capabilities = {}  # Dict of capability: PermissionValue
        self.allowed_indexes = {}  # Dict of allowed index: PermissionValue
        self.disallowed_indexes = {}  # Dict of disallowed index: PermissionValue
        self.misc = {}  # Dict of misc setting: PermissionValue
        self.inherited = []  # List of inherited role names
        self.inherited_roles = []  # List of inherited Role objects
        self.index_conflicts = []  # Conflicting indexes for this role
        self.capability_conflicts = []  # Conflicting capabilities for this role
        self.is_inherited = is_inherited

    def update_from_perms(self, perms, source_role):
        """Update role attributes from parsed btool permissions."""
        for attr, data in perms.items():
            if attr == "inherited":
                self.inherited = data
            elif attr in ("capabilities", "allowed_indexes", "disallowed_indexes", "misc"):
                getattr(self, attr).update({k: PermissionValue(source_role, f, l) for k, (f, l) in data.items()})

    def get_role_permissions_btool(self, splunk_bin, verbose, user_roles):
        """Extract role permissions from btool output, compatible with Python 3.6."""
        cmd = [splunk_bin, "btool", "authorize", "list", "--debug"]
        if verbose >= 3:
            print(f"DEBUG: Running: {' '.join(cmd)}")
        try:
            # Use stdout=PIPE and universal_newlines=True for Python 3.6 compatibility
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, check=True)
            output = result.stdout.strip()
            if verbose >= 3:
                print(f"DEBUG: btool output: {output[:1000]}...")
        except subprocess.CalledProcessError as e:
            print(f"Error running btool: {e}")
            return None

        roles = {}
        file_pattern = re.compile(r"^\s*(/.*?)\s+(\S+)\s*=\s*(.*)$")
        role_pattern = re.compile(r"^\s*/.*?\s+\[(.+?)\]\s*$")

        # Define parsing actions as a dictionary of lambdas
        actions = {
            "importRoles": lambda t, v, s: t["inherited"].extend(v.strip() for v in v.split(";") if v.strip()),
            "srchIndexesAllowed": lambda t, v, s: t["allowed_indexes"].update(
                {v.strip(): s for v in v.split(";") if v.strip()}
            ),
            "srchIndexesDisallowed": lambda t, v, s: t["disallowed_indexes"].update(
                {v.strip(): s for v in v.split(";") if v.strip()}
            ),
        }

        current_role = None
        for line_num, line in enumerate(output.splitlines(), 1):
            line = line.strip()
            if not line:
                continue

            role_match = role_pattern.match(line)
            if role_match:
                current_role = role_match.group(1)[len("role_"):]
                roles[current_role] = {"capabilities": {}, "allowed_indexes": {},
                                      "disallowed_indexes": {}, "misc": {}, "inherited": []}
                continue

            file_match = file_pattern.match(line)
            if current_role and file_match:
                file_path, key, value = file_match.groups()
                value = value.strip().lower()
                source = (file_path.strip(), line_num)
                target = roles[current_role]
                if "enabled" in value or "disabled" in value:
                    cap_key = key if value == "enabled" else f"{key}::disabled"
                    target["capabilities"][cap_key] = source
                else:
                    actions.get(key, lambda t, v, s: t["misc"].update({f"{key} = {v}": s}))(target, value, source)
                if verbose >= 3:
                    print(f"DEBUG: Parsed {key} = {value} for {current_role} from {file_path}:{line_num}")

        if verbose >= 1:
            print(f"Parsed {len(roles)} roles from btool: {', '.join(roles.keys()) or 'None'}")
        return roles.get(self.name)

def get_session_key(splunk_host, username, password, verbose=0):
    """Authenticate to Splunk REST API and return session key."""
    url = f"{splunk_host}/services/auth/login"
    if verbose >= 3:
        print(f"DEBUG: POST to {url} with username={username}")
    try:
        response = requests.post(url, data={"username": username, "password": password}, verify=False)
        response.raise_for_status()
        session_key = ET.fromstring(response.text).findtext("sessionKey")
        if not session_key:
            raise ValueError("No session key found in response")
        return session_key
    except (requests.RequestException, ET.ParseError) as e:
        if verbose >= 3 and isinstance(e, requests.RequestException) and 'response' in locals():
            print(f"DEBUG: Response content: {response.text}")
        raise Exception(f"Failed to authenticate: {e}")

def main():
    """Parse command-line arguments and run the permission checker."""
    parser = argparse.ArgumentParser(description="Check Splunk user permissions using btool")
    parser.add_argument("-u", "--url", default="https://localhost:8089",
                        help="Splunk REST API URL (default: https://localhost:8089)")
    parser.add_argument("-U", "--username", help="Splunk admin username")
    parser.add_argument("-p", "--password", help="Splunk admin password")
    parser.add_argument("-t", "--target_user", required=True, help="User to check permissions for")
    parser.add_argument("-b", "--splunk_bin", default="/opt/splunk/bin/splunk",
                        help="Path to splunk binary (default: /opt/splunk/bin/splunk)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbosity level (repeat for more detail)")
    args = parser.parse_args()

    splunk_host = args.url
    username = args.username if args.username is not None else input("Enter Splunk username: ")
    password = args.password if args.password is not None else getpass.getpass("Enter Splunk password: ")

    if args.verbose >= 3:
        print(f"DEBUG: splunk_host={splunk_host}, username={username}, target_user={args.target_user}")

    user = User(args.target_user)
    user.populate_user(splunk_host, username, password, args.splunk_bin, args.verbose)
    user.print_results(args.verbose)

if __name__ == "__main__":
    main()
