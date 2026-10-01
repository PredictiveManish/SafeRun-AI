"""
Policy engine for loading YAML rules and checking compliance.
Integrates with scanner results and code.
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any
from backend.scanner import ScanResult, NETWORK_MODULES


class PolicyEngine:
    """Loads policy from YAML and evaluates code against it."""

    def __init__(self, policy_path: str):
        self.policy_path = Path(policy_path)
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict[str, Any]:
        """Load YAML policy file. Return default if missing."""
        default_policy = {
            "max_execution_time_seconds": 10,
            "max_memory_mb": 256,
            "max_cpu_cores": 1,
            "max_code_size_kb": 100,
            "network_enabled": False,
            "filesystem_write_enabled": False,
            "allowed_imports": ["math", "random", "datetime", "json", "re"],
            "blocked_imports": [
                "os",
                "subprocess",
                "socket",
                "requests",
                "urllib",
                "shutil",
                "importlib",
                "pickle",
            ],
            "blocked_calls": [
                "eval",
                "exec",
                "compile",
                "__import__",
                "subprocess.run",
                "subprocess.Popen",
                "os.system",
                "os.remove",
                "shutil.rmtree",
            ],
        }
        if not self.policy_path.exists():
            # Write default for future
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.policy_path, "w") as f:
                yaml.safe_dump(default_policy, f, default_flow_style=False)
            return default_policy

        with open(self.policy_path, "r") as f:
            loaded = yaml.safe_load(f)
            # Merge with defaults for missing keys
            for k, v in default_policy.items():
                if k not in loaded:
                    loaded[k] = v
            return loaded

    def check_code(self, code: str, scan_result: ScanResult) -> List[str]:
        """
        Check code against policy rules.
        Returns list of policy violation descriptions.

        Uses the scanner's exact-match fields (detected_imports,
        detected_calls) instead of re-parsing pattern strings. The old
        pattern parsing had a bug: for `from X import Y` the pattern is
        "import_from_X", and splitting on the first underscore yielded
        "from_X", which never matched blocked_imports — so from-import
        violations were silently missed.
        """
        violations = []

        # Code size check
        code_size_kb = len(code.encode("utf-8")) / 1024
        if code_size_kb > self.policy["max_code_size_kb"]:
            violations.append(
                f"Code size exceeds policy limit: {code_size_kb:.1f} KB > {self.policy['max_code_size_kb']} KB"
            )

        # Blocked imports (exact match on module roots, covers both
        # `import X` and `from X import Y`)
        for import_name in scan_result.detected_imports:
            if import_name in self.policy["blocked_imports"]:
                violations.append(f"Blocked import: {import_name}")

        # Blocked calls (exact dotted-name match; no endswith matching,
        # which previously caused false positives like my_eval)
        for call_name in scan_result.detected_calls:
            if call_name in self.policy["blocked_calls"]:
                violations.append(f"Blocked call: {call_name}")

        # Check network policy
        if not self.policy["network_enabled"] and any(
            import_name in NETWORK_MODULES for import_name in scan_result.detected_imports
        ):
            violations.append(
                "Network access is disabled by policy but code imports networking module"
            )

        # Check filesystem write policy
        if (
            not self.policy["filesystem_write_enabled"]
            and "file_write" in scan_result.detected_patterns
        ):
            violations.append(
                "Filesystem write access is disabled by policy but code attempts to write files"
            )

        return violations

    def get_max_execution_time(self) -> int:
        return self.policy.get("max_execution_time_seconds", 10)

    def get_max_memory_mb(self) -> int:
        return self.policy.get("max_memory_mb", 256)

    def get_max_cpu_cores(self) -> float:
        return float(self.policy.get("max_cpu_cores", 1))

    def get_network_enabled(self) -> bool:
        return self.policy.get("network_enabled", False)

    def get_filesystem_write_enabled(self) -> bool:
        return self.policy.get("filesystem_write_enabled", False)
