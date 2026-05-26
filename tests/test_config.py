"""
Tests for config module.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.config import Settings


def test_settings_defaults():
    """Test that settings have reasonable defaults."""
    settings = Settings()
    
    # Test attributes that actually exist
    assert hasattr(settings, 'backend_host')
    assert hasattr(settings, 'backend_port')
    assert hasattr(settings, 'database_url')
    assert hasattr(settings, 'sandbox_image')
    
    assert settings.backend_host == "0.0.0.0"
    assert settings.backend_port == 8000
    assert settings.database_url == "sqlite:///./saferun.db"


def test_settings_from_env(monkeypatch):
    """Test that settings can be overridden by environment variables."""
    monkeypatch.setenv("BACKEND_PORT", "9000")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///test.db")
    
    settings = Settings()
    
    assert settings.backend_port == 9000
    assert settings.database_url == "sqlite:///test.db"