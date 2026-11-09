"""
Tests for API authentication, request limits and output truncation.

These are the guarantees that make the API safe to expose: no key, no work;
no admin key, no policy override; no unbounded output or history.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.main import app
from backend.sandbox import ExecutionResult, cap_output

KEY = {"X-API-Key": "test-key"}
ADMIN = {"X-API-Key": "test-key", "X-Admin-Key": "test-admin-key"}
BLOCKED_CODE = "import os\nos.system('echo hello')\n"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------- /scan
def test_scan_without_key_is_rejected(client):
    resp = client.post("/scan", json={"code": "print(1)"})
    assert resp.status_code == 401


def test_scan_with_wrong_key_is_rejected(client):
    resp = client.post("/scan", json={"code": "print(1)"}, headers={"X-API-Key": "nope"})
    assert resp.status_code == 401


def test_scan_with_key_succeeds(client):
    resp = client.post("/scan", json={"code": "print('hello')"}, headers=KEY)
    assert resp.status_code == 200
    assert resp.json()["risk_level"] in {"LOW", "MEDIUM", "HIGH", "BLOCKED"}


def test_no_configured_key_returns_503(client, monkeypatch):
    """A server with no key must refuse to serve, not serve openly."""
    monkeypatch.setattr(settings, "api_keys", None)
    resp = client.post("/scan", json={"code": "print(1)"}, headers=KEY)
    assert resp.status_code == 503


# ------------------------------------------------------------------ /execute
def test_blocked_code_is_refused(client):
    resp = client.post("/execute", json={"code": BLOCKED_CODE}, headers=KEY)
    assert resp.status_code == 403


def test_override_without_admin_key_is_refused(client):
    """The client cannot switch the policy engine off by itself."""
    resp = client.post(
        "/execute", json={"code": BLOCKED_CODE, "override": True}, headers=KEY
    )
    assert resp.status_code == 403
    assert "admin" in resp.json()["detail"].lower()


def test_override_with_admin_key_reaches_the_sandbox(client, monkeypatch):
    """With the admin key the request proceeds (sandbox stubbed, no Docker)."""
    calls = {}

    def fake_execute(**kwargs):
        calls.update(kwargs)
        return ExecutionResult(
            status="success",
            stdout="stubbed",
            stderr="",
            exit_code=0,
            execution_time=0.01,
            container_status="completed",
        )

    monkeypatch.setattr(
        "backend.main.sandbox", types.SimpleNamespace(execute=fake_execute)
    )
    resp = client.post(
        "/execute", json={"code": BLOCKED_CODE, "override": True}, headers=ADMIN
    )
    assert resp.status_code == 200
    assert resp.json()["blocked"] is True
    assert resp.json()["stdout"] == "stubbed"
    # The policy's output cap must be passed down to the executor.
    assert calls["max_output_bytes"] == settings.max_output_bytes


def test_truncation_flags_are_reported(client, monkeypatch):
    def fake_execute(**kwargs):
        return ExecutionResult(
            status="success",
            stdout="x",
            stderr="",
            exit_code=0,
            execution_time=0.01,
            container_status="completed",
            stdout_truncated=True,
        )

    monkeypatch.setattr(
        "backend.main.sandbox", types.SimpleNamespace(execute=fake_execute)
    )
    resp = client.post("/execute", json={"code": "print(1)"}, headers=KEY)
    assert resp.status_code == 200
    assert resp.json()["stdout_truncated"] is True
    assert resp.json()["stderr_truncated"] is False


# ------------------------------------------------------------------ /history
def test_history_requires_key(client):
    assert client.get("/history").status_code == 401


def test_history_limit_is_bounded(client):
    assert client.get("/history", params={"limit": 5}, headers=KEY).status_code == 200
    assert (
        client.get("/history", params={"limit": 100000}, headers=KEY).status_code == 422
    )
    assert client.get("/history", params={"limit": 0}, headers=KEY).status_code == 422


# ------------------------------------------------------------ output capping
def test_cap_output_truncates_long_text():
    text, truncated = cap_output("x" * 100, 10)
    assert truncated is True
    assert text.startswith("x" * 10)
    assert "truncated" in text


def test_cap_output_leaves_short_text_alone():
    text, truncated = cap_output("short", 10)
    assert truncated is False
    assert text == "short"


def test_cap_output_is_utf8_safe():
    text, truncated = cap_output("é" * 50, 11)
    assert truncated is True
    assert "truncated" in text
