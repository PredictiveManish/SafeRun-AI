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
    "sockets",
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

DANGEROURS_CALLS = {
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
