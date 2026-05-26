"""
AST-based static code scanner.
Detects dangerous imports, calls, patterns, and infinite loops.
"""

import ast
import hashlib
from typing import List, Set, Tuple
from dataclasses import dataclass, field

# Dangerous patterns
DANGEROUS_IMPORTS = {
    "os",
    "subprocess",
    "socket",
    "requests",
    "urllib",
    "urllib3",
    "shutil",
    "importlib",
    "pickle",
    "shelve",
    "pty",
    "fcntl",
    "ctypes",
    "winreg",
    "msvcrt",
}

DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system",
    "os.popen",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "shutil.rmtree",
    "shutil.move",
    "open",  # special handling for write mode
}

SUSPICIOUS_PATHS = {
    "/etc",
    "/root",
    "/home",
    "/var",
    "~/.ssh",
    ".env",
    "C:\\Windows",
    "C:\\System32",
    "\System",
    "\Library",
}

# Additionl call patterns
WRITE_MODE_NAMES = {"w", "wb", "a", "ab", "w+", "a+", "x"}


@dataclass
class ScanResult:
    """Result  of static code scan."""

    risk_level: str  # LOW, MEDIUM, HIGH, BLOCKED
    blocked: bool
    warnings: List[str] = field(default_factory=list)
    detected_patterns: List[str] = field(default_factory=list)


class CodeScanner:
    """AST Scanner for security analysis"""

    def scan(self, code: str) -> ScanResult:
        """
        Scan Python code and return risk assessment.
        """
        if not code or not code.strip():
            return ScanResult(
                risk_level="LOW",
                blocked=False,
                warnings=["Empty code provided"],
                detected_patterns=["empty"],
            )

        # Check code size (heuristic)
        if len(code) > 100 * 1024:  # 100KB
            return ScanResult(
                risk_level="HIGH",
                blocked=True,
                warnings=["Code exceeds maximum size limit"],
                detected_patterns=["size_exceeded"],
            )

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return ScanResult(
                risk_level="HIGH",
                blocked=True,
                warnings=[f"Syntax error: {str(e)}"],
                detected_patterns=["syntax_error"],
            )

        warnings = []
        patterns = []
        risk_score = 0  # 0-10, higher = more dangerous
        blocked = False

        # Analyze AST
        for node in ast.walk(tree):
            # Dangerous imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name.split(".")[0]

                    if name in DANGEROUS_IMPORTS:
                        warnings.append(f"Dangerous import: {name}")
                        patterns.append(f"import_{name}")
                        risk_score += 2
                        blocked = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module.split(".")[0] if node.module else ""
                if module in DANGEROUS_IMPORTS:
                    warnings.append(f"Dangerous import from: {module}")
                    patterns.append(f"import_from_{module}")
                    risk_score += 2
                    blocked = True

            # Dangerous function calls
            elif isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                if func_name in DANGEROUS_CALLS:
                    # Special case: open with write mode
                    if func_name == "open":
                        if self._is_write_mode(node):
                            warnings.append("File write operation detected.")
                            patterns.append("file_write")
                            risk_score += 2
                            if not blocked:  # Write may be allowed by policy, but scanner flags as HIGH
                                blocked = False  # not auto-block; policy decides
                            else:
                                warnings.append(f"Dangerous call: {func_name}")
                                patterns.append(f"call_{func_name.replace('.', '_')}")
                                risk_score += 3
                                blocked = True

                    # Suspicious string literals (paths)
                    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                        path = node.value
                        for susp in SUSPICIOUS_PATHS:
                            if susp in path and len(path) > 3:
                                warnings.append(
                                    f"Suspicious path reference: {path[:50]}"
                                )
                                patterns.append("suspicious_path")
                                risk_score += 1

                        # Detec infinite loop candidates (while True with no break detection is heuristic)
                    elif isinstance(node, ast.While):
                        if (
                            isinstance(node.test, ast.Constant)
                            and node.test.value is True
                        ):
                            # Check for break/return inside body (simplistic)
                            has_exit = any(
                                isinstance(sub, (ast.Break, ast.Return))
                                for sub in ast.walk(node)
                            )
                            if not has_exit:
                                warnings.append(
                                    "Potential infinite loop: 'while True' without break"
                                )
                                patterns.append("infinite_loop")
                                risk_score += 2
                # Determine risk level
                if blocked:
                    risk_level = "BLOCKED"
                elif risk_score >= 5:
                    risk_level = "HIGH"
                elif risk_score >= 2:
                    risk_level = "MEDIUM"
                else:
                    risk_level = "LOW"

                # Remove duplicates
                warnings = list(dict.fromkeys(warnings))
                patterns = list(dict.fromkeys(patterns))

                return ScanResult(
                    risk_level=risk_level,
                    blocked=blocked,
                    warnings=warnings,
                    detected_patterns=patterns,
                )

    def _get_func_name(self, node) -> str:
        """Extract fully qualified function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Recursively build name
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return "unknown"

    def _is_write_mode(self, call_node: ast.Call) -> bool:
        """Check if open() call has write mode."""
        if len(call_node.args) >= 2:
            mode_arg = call_node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                return any(mode in mode_arg.value for mode in WRITE_MODE_NAMES)

        # check keyword arg 'mode'
        for kw in call_node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, str):
                    return any(mode in kw.value.value for mode in WRITE_MODE_NAMES)
        return False
