import ast
from scanner import CodeScanner, ScanResult

def test_imports():
    """Test that only dangerous imports are flagged"""
    scanner = CodeScanner()
    
    # Test safe import - should not trigger warning
    safe_code = """
import math
import json
"""
    result = scanner.scan(safe_code)
    print(f"Safe imports: risk_level={result.risk_level}, warnings={result.warnings}")
    assert result.risk_level == "LOW", f"Expected LOW risk, got {result.risk_level}"
    assert len(result.warnings) == 0, f"Expected no warnings, got {result.warnings}"
    
    # Test dangerous import - should trigger warning
    dangerous_code = """
import os
"""
    result = scanner.scan(dangerous_code)
    print(f"Dangerous import: risk_level={result.risk_level}, warnings={result.warnings}")
    assert result.risk_level == "BLOCKED", f"Expected BLOCKED risk, got {result.risk_level}"
    assert any("Dangerous import: os" in w for w in result.warnings), f"Expected os import warning, got {result.warnings}"

def test_import_from():
    """Test ImportFrom statements"""
    scanner = CodeScanner()
    
    # Test safe import from
    safe_code = """
from math import sqrt
"""
    result = scanner.scan(safe_code)
    print(f"Safe import from: risk_level={result.risk_level}, warnings={result.warnings}")
    assert result.risk_level == "LOW", f"Expected LOW risk, got {result.risk_level}"
    
    # Test dangerous import from
    dangerous_code = """
from os import path
"""
    result = scanner.scan(dangerous_code)
    print(f"Dangerous import from: risk_level={result.risk_level}, warnings={result.warnings}")
    assert result.risk_level == "BLOCKED", f"Expected BLOCKED risk, got {result.risk_level}"
    assert any("Dangerous import from: os" in w for w in result.warnings), f"Expected os import from warning, got {result.warnings}"

def test_string_literals():
    """Test that suspicious path detection works for all string literals, not just in calls"""
    scanner = CodeScanner()
    
    # Test suspicious string in variable assignment (should trigger)
    suspicious_code = """
bad_path = "/etc/passwd"
"""
    result = scanner.scan(suspicious_code)
    print(f"Suspicious string: risk_level={result.risk_level}, warnings={result.warnings}")
    # Should have at least LOW risk due to the suspicious path
    assert result.risk_level in ["LOW", "MEDIUM", "HIGH", "BLOCKED"], f"Expected some risk, got {result.risk_level}"
    assert any("Suspicious path reference" in w for w in result.warnings), f"Expected suspicious path warning, got {result.warnings}"
    
    # Test safe string (should not trigger)
    safe_string_code = """
safe_string = "hello world"
"""
    result = scanner.scan(safe_string_code)
    print(f"Safe string: risk_level={result.risk_level}, warnings={result.warnings}")
    assert result.risk_level == "LOW", f"Expected LOW risk, got {result.risk_level}"
    assert len(result.warnings) == 0, f"Expected no warnings, got {result.warnings}"

def test_infinite_loop():
    """Test that infinite loop detection works outside of Call nodes"""
    scanner = CodeScanner()
    
    # Test infinite loop (should trigger)
    infinite_loop_code = """
while True:
    x = x + 1
"""
    result = scanner.scan(infinite_loop_code)
    print(f"Infinite loop: risk_level={result.risk_level}, warnings={result.warnings}")
    assert result.risk_level in ["LOW", "MEDIUM", "HIGH", "BLOCKED"], f"Expected some risk, got {result.risk_level}"
    assert any("Potential infinite loop" in w for w in result.warnings), f"Expected infinite loop warning, got {result.warnings}"
    
    # Test loop with break (should not trigger infinite loop warning)
    loop_with_break_code = """
while True:
    if condition:
        break
    x = x + 1
"""
    result = scanner.scan(loop_with_break_code)
    print(f"Loop with break: risk_level={result.risk_level}, warnings={result.warnings}")
    # May still have other warnings, but should not have infinite loop warning
    infinite_loop_warnings = [w for w in result.warnings if "Potential infinite loop" in w]
    assert len(infinite_loop_warnings) == 0, f"Expected no infinite loop warnings, got {infinite_loop_warnings}"

if __name__ == "__main__":
    test_imports()
    test_import_from()
    test_string_literals()
    test_infinite_loop()
    print("All tests passed!")