"""
Tests for policy_engine module.
"""
import sys
import os
import tempfile
import yaml
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.policy_engine import PolicyEngine
from backend.scanner import ScanResult


def test_policy_engine_init_with_defaults():
    """Test PolicyEngine creates default policy when file doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test_policy.yaml")
        
        # Policy file doesn't exist yet
        assert not os.path.exists(policy_path)
        
        engine = PolicyEngine(policy_path)
        
        # Should have created default policy
        assert os.path.exists(policy_path)
        assert engine.policy["max_execution_time_seconds"] == 10
        assert engine.policy["max_memory_mb"] == 256
        assert "os" in engine.policy["blocked_imports"]
        assert "eval" in engine.policy["blocked_calls"]


def test_policy_engine_load_existing():
    """Test PolicyEngine loads existing policy file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test_policy.yaml")
        
        # Create a custom policy
        custom_policy = {
            "max_execution_time_seconds": 30,
            "max_memory_mb": 512,
            "network_enabled": True,
            "filesystem_write_enabled": True,
            "allowed_imports": ["math", "os"],
            "blocked_imports": ["subprocess"],
            "blocked_calls": ["eval", "exec"]
        }
        
        with open(policy_path, 'w') as f:
            yaml.dump(custom_policy, f)
        
        engine = PolicyEngine(policy_path)
        
        # Should have loaded custom policy and merged with defaults
        assert engine.policy["max_execution_time_seconds"] == 30  # custom
        assert engine.policy["max_cpu_cores"] == 1  # default (not in custom)
        assert engine.policy["network_enabled"] is True  # custom
        assert "os" in engine.policy["allowed_imports"]  # custom
        assert "math" in engine.policy["allowed_imports"]  # custom
        assert "subprocess" in engine.policy["blocked_imports"]  # custom
        assert "eval" in engine.policy["blocked_calls"]  # custom


def test_policy_engine_check_code():
    """Test policy engine violation detection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test_policy.yaml")
        engine = PolicyEngine(policy_path)
        
        # Create a scan result with dangerous import
        scan_result = ScanResult(
            risk_level="BLOCKED",
            blocked=True,
            warnings=["Dangerous import: os"],
            detected_patterns=["import_os"]
        )
        
        violations = engine.check_code("import os", scan_result)
        
        # Should detect blocked import
        assert len(violations) > 0
        assert any("Blocked import: os" in v for v in violations)


def test_policy_engine_check_code_no_violations():
    """Test policy engine with compliant code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test_policy.yaml")
        engine = PolicyEngine(policy_path)
        
        # Create a scan result with safe import
        scan_result = ScanResult(
            risk_level="LOW",
            blocked=False,
            warnings=[],
            detected_patterns=["import_math"]
        )
        
        violations = engine.check_code("import math", scan_result)
        
        # Should not detect violations for allowed import
        assert len(violations) == 0


def test_policy_engine_getters():
    """Test policy engine getter methods."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test_policy.yaml")
        engine = PolicyEngine(policy_path)
        
        # Test getters return expected types and values
        assert isinstance(engine.get_max_execution_time(), int)
        assert isinstance(engine.get_max_memory_mb(), int)
        assert isinstance(engine.get_max_cpu_cores(), float)
        assert isinstance(engine.get_network_enabled(), bool)
        assert isinstance(engine.get_filesystem_write_enabled(), bool)
        
        # Test default values
        assert engine.get_max_execution_time() == 10
        assert engine.get_max_memory_mb() == 256
        assert engine.get_max_cpu_cores() == 1.0