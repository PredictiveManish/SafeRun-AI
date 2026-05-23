"""
Utility functions for backend.
"""

import hashlib
import re
from typing import List


def hash_code(code: str) -> str:
    """Return SHA256 hash of code string."""
    return hashlib.sha256(code.encode()).hexdigest()


def truncate_string(s: str, max_len: int = 500) -> str:
    """Truncate string for logging."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


def sanitize_log(text: str) -> str:
    """Remove sensitive patterns from logs."""
    # Remove potential API keys or secrets (simple pattern)
    patterns = [
        (r"(api[_-]?key['\"]?\s*[:=]\s*['\"])[^'\"]+(['\"])", r"\1[REDACTED]\2"),
        (r"(token['\"]?\s*[:=]\s*['\"])[^'\"]+(['\"])", r"\1[REDACTED]\2"),
    ]
    for pat, repl in patterns:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text
