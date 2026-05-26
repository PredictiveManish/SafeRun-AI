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
    
    # Test that essential attributes exist
    assert hasattr(settings, 'APP_NAME')
    assert hasattr(settings, 'DEBUG')
    assert hasattr(settings, 'DATABASE_URL')
    assert hasattr(settings, 'MAX_CODE_SIZE')
    
    # Test default values are sensible
    assert settings.APP_NAME == "SafeRun AI"
    assert isinstance(settings.DEBUG, bool)
    assert settings.MAX_CODE_SIZE > 0


def test_settings_from_env(monkeypatch):
    """Test that settings can be overridden by environment variables."""
    # Set environment variables
    monkeypatch.setenv("APP_NAME", "TestApp")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("MAX_CODE_SIZE", "5000")
    
    # Create new settings instance
    settings = Settings()
    
    # Check that environment values were used
    assert settings.APP_NAME == "TestApp"
    assert settings.DEBUG is True
    assert settings.MAX_CODE_SIZE == 5000