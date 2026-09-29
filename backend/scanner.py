"""
AST-based static code scanner.
Detects dangerous imports, calls, patterns, aliasing bypasses, and infinite loops.
"""

import ast
from typing import List
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
    "builtins",  # escape hatch to every dangerous builtin
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
    "open",  # special handling: only write mode is flagged
}

# Bare builtin names that are dangerous when called directly OR aliased
DANGEROUS_BARE_NAMES = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "breakpoint",
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
    "\\System",
    "\\Library",
}

# Additional call patterns
WRITE_MODE_NAMES = {"w", "wb", "a", "ab", "w+", "a+", "x"}

# Modules that imply network access
NETWORK_MODULES = {"socket", "requests", "urllib", "urllib3", "http"}


@dataclass
class ScanResult:
    """Result of static code scan."""

    risk_level: str  # LOW, MEDIUM, HIGH, BLOCKED
    blocked: bool
    warnings: List[str] = field(default_factory=list)
    detected_patterns: List[str] = field(default_factory=list)
    # Exact module roots of dangerous imports (e.g. "os", "subprocess").
    # Consumed by the policy engine instead of re-parsing pattern strings.
    detected_imports: List[str] = field(default_factory=list)
    # Exact dotted call names of dangerous calls (e.g. "subprocess.run").
    # Consumed by the policy engine instead of re-parsing pattern strings.
    detected_calls: List[str] = field(default_factory=list)


class CodeScanner:
    """AST Scanner for security analysis."""

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
        detected_imports = []
        detected_calls = []
        risk_score = 0  # 0-10, higher = more dangerous
        blocked = False

        nodes = list(ast.walk(tree))

        # ------------------------------------------------------------------
        # Pass 1: collect dangerous aliases BEFORE analyzing calls.
        # Catches bypasses like:  f = eval; f("...")   or   d = os.system
        # ------------------------------------------------------------------
        aliases = {}  # local name -> dangerous function it is bound to
        for node in nodes:
            if isinstance(node, ast.Assign):
                rhs = node.value
                rhs_name = None
                if isinstance(rhs, (ast.Name, ast.Attribute)):
                    rhs_name = self._get_func_name(rhs)
                if rhs_name and (
                    rhs_name in DANGEROUS_CALLS or rhs_name in DANGEROUS_BARE_NAMES
                ):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            aliases[target.id] = rhs_name
                            warnings.append(
                                f"Dangerous call aliased: {target.id} = {rhs_name}"
                            )
                            patterns.append("aliased_call")
                            risk_score += 2
                            blocked = True

        # ------------------------------------------------------------------
        # Pass 2: analyze all nodes.
        # ------------------------------------------------------------------
        for node in nodes:
            # Dangerous imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name.split(".")[0]

                    if name in DANGEROUS_IMPORTS:
                        warnings.append(f"Dangerous import: {name}")
                        patterns.append(f"import_{name}")
                        detected_imports.append(name)
                        risk_score += 2
                        blocked = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module.split(".")[0] if node.module else ""
                if module in DANGEROUS_IMPORTS:
                    warnings.append(f"Dangerous import from: {module}")
                    patterns.append(f"import_from_{module}")
                    detected_imports.append(module)
                    risk_score += 2
                    blocked = True

            # Function calls
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)

                # Call to a name that was aliased from a dangerous function
                # (e.g. f = eval; f("1+1"))
                if func_name in aliases:
                    warnings.append(
                        f"Call to aliased dangerous function: {func_name}() "
                        f"(alias of {aliases[func_name]})"
                    )
                    patterns.append("aliased_call_invoked")
                    detected_calls.append(aliases[func_name])
                    risk_score += 3
                    blocked = True

                # open() — only WRITE mode is risky. Reads are harmless
                # (the sandbox rootfs is read-only anyway), so read-mode
                # open() is not flagged at all.
                if func_name == "open" or (
                    func_name in aliases and aliases[func_name] == "open"
                ):
                    if self._is_write_mode(node):
                        warnings.append("File write operation detected.")
                        patterns.append("file_write")
                        detected_calls.append("open")
                        risk_score += 2
                        # Not auto-blocked: the filesystem_write_enabled
                        # policy decides.

                # Dynamic access to dangerous builtins, including
                # constant-folded strings: getattr(__builtins__, "ev"+"al")
                elif func_name == "getattr" and node.args:
                    base = None
                    if isinstance(node.args[0], (ast.Name, ast.Attribute)):
                        base = self._get_func_name(node.args[0])
                    if base in ("builtins", "__builtins__"):
                        attr = None
                        if len(node.args) > 1:
                            attr = self._fold_string(node.args[1])
                        if attr in DANGEROUS_BARE_NAMES:
                            warnings.append(
                                f"Dynamic access to dangerous builtin via "
                                f"getattr: {attr}"
                            )
                            patterns.append("getattr_dynamic")
                            detected_calls.append(attr)
                            risk_score += 3
                            blocked = True

                # Direct dangerous calls
                elif func_name in DANGEROUS_CALLS and func_name != "open":
                    warnings.append(f"Dangerous call: {func_name}")
                    patterns.append(f"call_{func_name.replace('.', '_')}")
                    detected_calls.append(func_name)
                    risk_score += 3
                    blocked = True

            # Suspicious string literals (paths) - check all string constants
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                path = node.value
                for susp in SUSPICIOUS_PATHS:
                    if susp in path and len(path) > 3:
                        warnings.append(f"Suspicious path reference: {path[:50]}")
                        patterns.append("suspicious_path")
                        risk_score += 1

            # Detect infinite loop candidates
            # (while True with no break detection is heuristic)
            if isinstance(node, ast.While):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
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

        # Determine risk level (after processing all nodes)
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
        detected_imports = list(dict.fromkeys(detected_imports))
        detected_calls = list(dict.fromkeys(detected_calls))

        return ScanResult(
            risk_level=risk_level,
            blocked=blocked,
            warnings=warnings,
            detected_patterns=patterns,
            detected_imports=detected_imports,
            detected_calls=detected_calls,
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

    def _fold_string(self, node) -> str | None:
        """
        Constant-fold string expressions like "ev" + "al" -> "eval".
        Returns the folded value, or None if the node is not a constant
        string expression.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._fold_string(node.left)
            right = self._fold_string(node.right)
            if left is not None and right is not None:
                return left + right
        return None
