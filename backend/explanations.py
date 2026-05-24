"""
Explanation generation: optional Sarvam AI with local fallback.

Sarvam AI docs: https://docs.sarvam.ai/api-reference-docs/chat/chat-completions
Auth: api-subscription-key header (sk_xxx format)
Models: sarvam-30b (64K ctx) | sarvam-105b (128K ctx) | sarvam-m (legacy)
"""

import logging
from typing import Optional, List, Literal

import requests

from backend.scanner import ScanResult
from backend.sandbox import ExecutionResult

logger = logging.getLogger(__name__)

# Supported Sarvam chat models
SarvamModel = Literal["sarvam-105b", "sarvam-30b", "sarvam-m"]

SARVAM_CHAT_URL = "https://api.sarvam.ai/v1/chat/completions"
DEFAULT_MODEL: SarvamModel = "sarvam-30b"
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_MAX_TOKENS = 512


class SarvamAPIError(Exception):
    """Raised when Sarvam AI API returns an error response."""
    pass


class ExplanationGenerator:
    """
    Generates human-readable explanations for code scan and execution results.

    Uses Sarvam AI (sarvam-30b / sarvam-105b) when an API key is provided,
    with automatic fallback to a local rule-based engine on failure.

    Authentication:
        Sarvam uses the 'api-subscription-key' header (sk_xxx format).
        Do NOT use 'Authorization: Bearer' — that will return 401/403.

    Args:
        api_key: Sarvam AI subscription key (sk_xxx). Leave None to use local only.
        model: Which Sarvam chat model to use. Defaults to 'sarvam-30b'.
        language: Target language for explanations. Sarvam supports 10+ Indic
                  languages + English. Pass BCP-47 codes e.g. 'hi-IN', 'en-IN'.
                  Defaults to 'en-IN' (English).
        max_tokens: Max tokens for Sarvam response. Defaults to 512.
        timeout: Request timeout in seconds. Defaults to 10.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: SarvamModel = DEFAULT_MODEL,
        language: str = "en-IN",
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.api_key = api_key
        self.model = model
        self.language = language
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.sarvam_enabled = bool(api_key)

        if self.sarvam_enabled:
            logger.info(
                f"Sarvam AI enabled — model={self.model}, language={self.language}"
            )
        else:
            logger.info("Sarvam AI disabled — using local explanation engine.")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def generate_scan_explanation(
        self,
        code: str,
        scan_result: ScanResult,
        policy_violations: List[str],
    ) -> str:
        """Return a human-readable explanation for static scan results."""
        if self.sarvam_enabled:
            try:
                return self._sarvam_scan_explanation(code, scan_result, policy_violations)
            except SarvamAPIError as e:
                logger.warning(f"Sarvam AI error, falling back to local: {e}")
            except requests.RequestException as e:
                logger.warning(f"Sarvam AI network error, falling back to local: {e}")
            except Exception as e:
                logger.warning(f"Sarvam AI unexpected error, falling back to local: {e}")

        return self._local_scan_explanation(scan_result, policy_violations)

    def generate_execution_explanation(
        self,
        code: str,
        scan_result: ScanResult,
        exec_result: ExecutionResult,
        policy_violations: List[str],
    ) -> str:
        """Return a human-readable explanation for sandbox execution results."""
        if self.sarvam_enabled:
            try:
                return self._sarvam_execution_explanation(
                    code, scan_result, exec_result, policy_violations
                )
            except SarvamAPIError as e:
                logger.warning(f"Sarvam AI error, falling back to local: {e}")
            except requests.RequestException as e:
                logger.warning(f"Sarvam AI network error, falling back to local: {e}")
            except Exception as e:
                logger.warning(f"Sarvam AI unexpected error, falling back to local: {e}")

        return self._local_execution_explanation(scan_result, exec_result, policy_violations)

    # ------------------------------------------------------------------ #
    # Sarvam AI — prompt builders
    # ------------------------------------------------------------------ #

    def _sarvam_scan_explanation(
        self,
        code: str,
        scan_result: ScanResult,
        violations: List[str],
    ) -> str:
        code_snippet = (code or "")[:500].strip() or "(empty)"
        violations_str = ", ".join(violations) if violations else "None"
        warnings_str = ", ".join(scan_result.warnings) if scan_result.warnings else "None"
        patterns_str = ", ".join(scan_result.detected_patterns) if scan_result.detected_patterns else "None"

        prompt = f"""You are a security expert reviewing AI-generated code.
Explain the following static analysis results in a concise paragraph (3-5 sentences) for a developer.

Risk level: {scan_result.risk_level}
Blocked: {scan_result.blocked}
Detected patterns: {patterns_str}
Warnings: {warnings_str}
Policy violations: {violations_str}

Code snippet:
{code_snippet}

Briefly explain: what risk was found, why it matters, and what the developer should do next.
Respond in language: {self.language}"""

        return self._call_sarvam(prompt)

    def _sarvam_execution_explanation(
        self,
        code: str,
        scan_result: ScanResult,
        exec_result: ExecutionResult,
        violations: List[str],
    ) -> str:
        code_snippet = (code or "")[:500].strip() or "(empty)"
        violations_str = ", ".join(violations) if violations else "None"
        warnings_str = ", ".join(scan_result.warnings) if scan_result.warnings else "None"
        stdout_snippet = (exec_result.stdout or "")[:300]
        stderr_snippet = (exec_result.stderr or "")[:300]

        prompt = f"""You are a security expert reviewing AI-generated code executed in a sandbox.
Explain the execution result in a concise paragraph (3-5 sentences) for a developer.

Risk level: {scan_result.risk_level}
Execution status: {exec_result.status}
Exit code: {exec_result.exit_code}
Execution time: {exec_result.execution_time:.2f}s
Stdout (truncated): {stdout_snippet or '(none)'}
Stderr (truncated): {stderr_snippet or '(none)'}
Warnings: {warnings_str}
Policy violations: {violations_str}

Briefly explain: what happened during execution, any errors or security concerns, and suggested next steps.
Respond in language: {self.language}"""

        return self._call_sarvam(prompt)

    # ------------------------------------------------------------------ #
    # Sarvam AI — HTTP client
    # ------------------------------------------------------------------ #

    def _call_sarvam(self, prompt: str) -> str:
        """
        Call the Sarvam AI chat completions endpoint.

        Auth note: Sarvam requires the 'api-subscription-key' header.
        Using 'Authorization: Bearer' alone will fail with 401/403.

        Raises:
            SarvamAPIError: on non-2xx HTTP responses.
            requests.RequestException: on network/timeout failures.
        """
        headers = {
            # Primary auth method per Sarvam docs
            "api-subscription-key": self.api_key,
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.2,       # low temp = focused, deterministic output
            "reasoning_effort": "low", # keep latency down for inline explanations
        }

        logger.debug(f"Calling Sarvam AI [{self.model}] prompt_len={len(prompt)}")

        response = requests.post(
            SARVAM_CHAT_URL,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )

        if not response.ok:
            raise SarvamAPIError(
                f"Sarvam API returned {response.status_code}: {response.text[:300]}"
            )

        data = response.json()

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise SarvamAPIError(f"Unexpected Sarvam response shape: {e} — {data}")

        if not content or not content.strip():
            raise SarvamAPIError("Sarvam returned an empty response.")

        return content.strip()

    # ------------------------------------------------------------------ #
    # Local fallback — rule-based explanations
    # ------------------------------------------------------------------ #

    def _local_scan_explanation(
        self,
        scan_result: ScanResult,
        violations: List[str],
    ) -> str:
        """Rule-based explanation for scan results (no API call required)."""
        violations = violations or []
        patterns = scan_result.detected_patterns or []
        warnings = scan_result.warnings or []

        if scan_result.blocked:
            pattern_str = ", ".join(patterns[:3]) or "unknown patterns"
            violation_str = (
                f" Policy violations: {', '.join(violations[:3])}." if violations else ""
            )
            return (
                f"❌ Code was blocked due to high-risk patterns: {pattern_str}."
                f"{violation_str} Execution is not permitted."
            )

        if scan_result.risk_level == "HIGH":
            warning_str = ", ".join(warnings[:2]) or "unspecified risks"
            return (
                f"⚠️ High-risk code detected: {warning_str}. "
                f"Review carefully before executing in any environment."
            )

        if scan_result.risk_level == "MEDIUM":
            warning_str = ", ".join(warnings[:2]) or "potential issues"
            return (
                f"ℹ️ Medium-risk patterns found: {warning_str}. "
                f"Consider reviewing this code before execution."
            )

        return "✅ Code appears safe based on static analysis."

    def _local_execution_explanation(
        self,
        scan_result: ScanResult,
        exec_result: ExecutionResult,
        violations: List[str] = None,
    ) -> str:
        """Rule-based explanation for execution results (no API call required)."""
        violations = violations or []

        if exec_result.status == "success":
            base = (
                f"✅ Code executed successfully in sandbox "
                f"(exit code {exec_result.exit_code}) "
                f"in {exec_result.execution_time:.2f}s."
            )
            if violations:
                base += (
                    f" Note: policy warnings remain active: "
                    f"{', '.join(violations[:2])}."
                )
            return base

        if exec_result.status == "timeout":
            return (
                "⏱️ Execution timed out. The code may contain an infinite loop "
                "or unexpectedly heavy computation. Review any loops and I/O calls."
            )

        if exec_result.status == "error":
            stderr = (exec_result.stderr or "").strip()[:200] or "No stderr captured."
            return (
                f"❌ Runtime error during sandbox execution: {stderr} "
                f"Check the code for logical or dependency issues."
            )

        return "❓ Unexpected execution outcome. Review the sandbox logs for details."