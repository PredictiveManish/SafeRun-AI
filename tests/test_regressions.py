"""
Regression tests for the security fixes:
1. Policy engine misses `from X import Y` violations (pattern-parsing bug)
2. Scanner aliasing bypass (f = eval; f("..."))
3. open() in read mode was auto-blocked (false positive)
4. Exact-match call policy (no endswith false positives like my_eval)
5. Dynamic builtin access via getattr with folded strings
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.scanner import CodeScanner
from backend.policy_engine import PolicyEngine


def _make_engine():
    tmpdir = tempfile.mkdtemp()
    return PolicyEngine(policy_path=os.path.join(tmpdir, "test_policy.yaml"))


# ---------------------------------------------------------------------------
# Fix 1: from-imports produce policy violations
# ---------------------------------------------------------------------------

def test_from_import_policy_violation():
    """`from subprocess import run` must be a policy violation (bug 1)."""
    scanner = CodeScanner()
    engine = _make_engine()

    code = "from subprocess import run\nrun('ls')"
    result = scanner.scan(code)
    assert result.detected_imports == ["subprocess"], result.detected_imports

    violations = engine.check_code(code, result)
    assert any("Blocked import: subprocess" in v for v in violations), violations


def test_plain_import_policy_violation_still_works():
    scanner = CodeScanner()
    engine = _make_engine()

    code = "import os"
    result = scanner.scan(code)
    violations = engine.check_code(code, result)
    assert any("Blocked import: os" in v for v in violations), violations


# ---------------------------------------------------------------------------
# Fix 2: aliasing bypass
# ---------------------------------------------------------------------------

def test_aliased_eval_is_blocked():
    """f = eval; f(...) must not slip past the scanner (bug 2)."""
    scanner = CodeScanner()
    code = "f = eval\nf('1+1')"
    result = scanner.scan(code)
    assert result.blocked is True
    assert result.risk_level == "BLOCKED"
    assert any("aliased" in w.lower() for w in result.warnings), result.warnings


def test_aliased_os_system_is_blocked():
    scanner = CodeScanner()
    code = "import os\nd = os.system\nd('ls')"
    result = scanner.scan(code)
    assert result.blocked is True
    assert result.risk_level == "BLOCKED"


def test_aliased_open_write_mode_detected():
    """w = open; w('out.txt', 'w') must be caught as a file write."""
    scanner = CodeScanner()
    code = "w = open\nw('out.txt', 'w')"
    result = scanner.scan(code)
    assert "file_write" in result.detected_patterns, result.detected_patterns
    assert "open" in result.detected_calls, result.detected_calls


# ---------------------------------------------------------------------------
# Fix 3: open() read mode no longer auto-blocked
# ---------------------------------------------------------------------------

def test_open_read_mode_not_blocked():
    scanner = CodeScanner()
    code = "print(open('data.txt').read())"
    result = scanner.scan(code)
    assert result.blocked is False
    assert result.risk_level == "LOW"
    assert result.warnings == [], result.warnings


def test_open_write_mode_flagged_not_auto_blocked():
    """Write mode sets file_write; the policy (not the scanner) decides."""
    scanner = CodeScanner()
    code = "open('out.txt', 'w')"
    result = scanner.scan(code)
    assert "file_write" in result.detected_patterns
    assert result.blocked is False  # policy decides via filesystem_write_enabled

    engine = _make_engine()
    violations = engine.check_code(code, result)
    assert any("Filesystem write" in v for v in violations), violations


# ---------------------------------------------------------------------------
# Fix 4: exact-match call policy
# ---------------------------------------------------------------------------

def test_my_eval_is_not_a_false_positive():
    """A user-defined function named my_eval must not match blocked call 'eval'."""
    scanner = CodeScanner()
    code = "def my_eval(x):\n    return x\nprint(my_eval(1))"
    result = scanner.scan(code)
    assert result.blocked is False
    assert "eval" not in result.detected_calls

    engine = _make_engine()
    violations = engine.check_code(code, result)
    assert not any("Blocked call" in v for v in violations), violations


def test_dunder_import_call_detected_exactly():
    scanner = CodeScanner()
    code = "os = __import__('os')"
    result = scanner.scan(code)
    assert "__import__" in result.detected_calls, result.detected_calls

    engine = _make_engine()
    violations = engine.check_code(code, result)
    assert any("Blocked call: __import__" in v for v in violations), violations


# ---------------------------------------------------------------------------
# Fix 5: dynamic builtin access via getattr (string folding)
# ---------------------------------------------------------------------------

def test_getattr_folded_string_bypass_blocked():
    """getattr(__builtins__, 'ev'+'al') must be caught."""
    scanner = CodeScanner()
    code = 'getattr(__builtins__, "ev" + "al")("1+1")'
    result = scanner.scan(code)
    assert result.blocked is True
    assert result.risk_level == "BLOCKED"
    assert "eval" in result.detected_calls, result.detected_calls


def test_getattr_plain_builtins_access_blocked():
    scanner = CodeScanner()
    code = 'getattr(__builtins__, "exec")("1")'
    result = scanner.scan(code)
    assert result.blocked is True


def test_builtins_import_blocked():
    """import builtins is an escape hatch to every dangerous builtin."""
    scanner = CodeScanner()
    code = "import builtins"
    result = scanner.scan(code)
    assert result.blocked is True
    assert "builtins" in result.detected_imports


# ---------------------------------------------------------------------------
# Existing behavior that must be preserved
# ---------------------------------------------------------------------------

def test_safe_code_still_low_risk():
    scanner = CodeScanner()
    code = "import math\nprint(math.sqrt(16))"
    result = scanner.scan(code)
    assert result.risk_level == "LOW"
    assert result.blocked is False
    assert result.warnings == []


def test_direct_eval_still_blocked():
    scanner = CodeScanner()
    code = "print(eval('1+1'))"
    result = scanner.scan(code)
    assert result.blocked is True
    assert "eval" in result.detected_calls


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  {name} passed")
    print("All regression tests passed!")
