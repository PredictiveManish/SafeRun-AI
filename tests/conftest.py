"""
Test bootstrap.

Authentication settings are read once, when backend.config is first imported,
so they have to be set before any test module imports the backend. conftest.py
is imported first, which makes this the right place for them.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("SAFERUN_API_KEYS", "test-key")
os.environ.setdefault("SAFERUN_ADMIN_KEY", "test-admin-key")
os.environ.setdefault("SAFERUN_ALLOW_ANONYMOUS", "0")
