"""
Tests for schemas module.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.schemas import (
    ScanRequest,
    ScanResponse,
    ExecuteRequest,
    HistoryEntry
)


def test_scan_request():
    """Test ScanRequest schema."""
    request = ScanRequest(code="print('hello')")
    assert request.code == "print('hello')"


def test_scan_response():
    """Test ScanResponse schema."""
    response = ScanResponse(
        risk_level="LOW",
        blocked=False,
        warnings=["test warning"],
        detected_patterns=["test_pattern"],
        policy_violations=[],
        explanation="test explanation"
    )
    assert response.risk_level == "LOW"
    assert response.blocked is False
    assert len(response.warnings) == 1
    assert response.explanation == "test explanation"


def test_execute_request():
    """Test ExecuteRequest schema."""
    request = ExecuteRequest(code="print('hello')", override=True)
    assert request.code == "print('hello')"
    assert request.override is True

    # Test default
    request_default = ExecuteRequest(code="print('hello')")
    assert request_default.override is False


def test_history_entry():
    """Test HistoryEntry schema."""
    entry = HistoryEntry(
        id=1,
        code_hash="abc123",
        risk_level="MEDIUM",
        blocked=True,
        warnings='["warning1", "warning2"]',
        stdout="test stdout",
        stderr="test stderr",
        exit_code=0,
        execution_time=1.5,
        status="success",
        created_at="2023-01-01T00:00:00"
    )
    assert entry.id == 1
    assert entry.code_hash == "abc123"
    assert entry.risk_level == "MEDIUM"
    assert entry.blocked is True
    assert entry.warnings == '["warning1", "warning2"]'
    assert entry.stdout == "test stdout"
    assert entry.stderr == "test stderr"
    assert entry.exit_code == 0
    assert entry.execution_time == 1.5
    assert entry.status == "success"
    assert entry.created_at == "2023-01-01T00:00:00"
    assert entry.code_hash == "abc123"
    assert entry.risk_level == "MEDIUM"
    assert entry.blocked is True