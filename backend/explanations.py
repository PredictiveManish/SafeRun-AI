"""
Explanation generation: optional Sarvam AI with local fallback.
"""

import os
import json
import logging
from typing import Optional, List, Dict, Any
import requests

from backend.scanner import ScanResult
from backend.sandbox import ExecutionResult

logger = logging.getLogger(__name__)


class ExplanationGenerator:
    """Generates human-readable explanations using Sarvam AI or local rules."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.sarvam_enabled = bool(api_key)
        if self.sarvam_enabled:
            logger.info("Sarvam AI integration enabled.")
        else:
            logger.info("Sarvam AI disabled, using local explanation engine.")

    def generate_scan_explanation(
        self, code: str, scan_result: ScanResult, policy_violations: List[str]
    ) -> str:
        """Return explanation for scan results."""
        if self.sarvam_enabled:
            try:
                return self._sarvam_scan_explanation(
                    code, scan_result, policy_violations
                )
            except Exception as e:
                logger.warning(f"Sarvam AI failed, falling back: {e}")
                return self._local_scan_explanation(scan_result, policy_violations)
        else:
            return self._local_scan_explanation(scan_result, policy_violations)

    def generate_execution_explanation(
        self,
        code: str,
        scan_result: ScanResult,
        exec_result: ExecutionResult,
        policy_violations: List[str],
    ) -> str:
        """Return explanation for execution results."""
        if self.sarvam_enabled:
            try:
                return self._sarvam_execution_explanation(
                    code, scan_result, exec_result, policy_violations
                )
            except Exception as e:
                logger.warning(f"Sarvam AI failed, falling back: {e}")
                return self._local_execution_explanation(
                    scan_result, exec_result, policy_violations
                )
        else:
            return self._local_execution_explanation(
                scan_result, exec_result, policy_violations
            )

    # --- Sarvam AI integration ---
    def _sarvam_scan_explanation(
        self, code: str, scan_result: ScanResult, violations: List[str]
    ) -> str:
        prompt = f"""
You are a security expert. Explain the following code scan results in a short, helpful paragraph for a developer.

Risk level: {scan_result.risk_level}
Blocked: {scan_result.blocked}
Warnings: {", ".join(scan_result.warnings)}
Detected patterns: {", ".join(scan_result.detected_patterns)}
Policy violations: {", ".join(violations)}

Code snippet (first 500 chars):
{code[:500]}

Give a concise explanation of the risks and why it was blocked or warned.
"""
        return self._call_sarvam(prompt)

    def _sarvam_execution_explanation(
        self,
        code: str,
        scan_result: ScanResult,
        exec_result: ExecutionResult,
        violations: List[str],
    ) -> str:
        prompt = f"""
You are a security expert. Explain the following sandbox execution result for AI-generated code.

Risk level: {scan_result.risk_level}
Execution status: {exec_result.status}
Exit code: {exec_result.exit_code}
Stdout: {exec_result.stdout[:500]}
Stderr: {exec_result.stderr[:500]}
Warnings: {", ".join(scan_result.warnings)}
Policy violations: {", ".join(violations)}

Provide debugging suggestions and security insights.
"""
        return self._call_sarvam(prompt)

    def _call_sarvam(self, prompt: str) -> str:
        """Call Sarvam AI API (mock for demo; replace with actual endpoint)."""
        # Note: Sarvam AI API endpoint is not publicly documented; adjust URL as needed.
        # This is a placeholder to demonstrate integration pattern.
        url = "https://api.sarvam.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "sarvam-1",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 200,
            "temperature": 0.3,
        }
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    # --- Local fallback explanations ---
    def _local_scan_explanation(
        self, scan_result: ScanResult, violations: List[str]
    ) -> str:
        if scan_result.blocked:
            return f"Code blocked due to high-risk patterns: {', '.join(scan_result.detected_patterns[:3])}. Policy violations: {', '.join(violations[:3])}. Execution not allowed."
        elif scan_result.risk_level == "HIGH":
            return f"High-risk code detected: {', '.join(scan_result.warnings[:2])}. Proceed with caution."
        elif scan_result.risk_level == "MEDIUM":
            return f"Medium-risk patterns found: {', '.join(scan_result.warnings[:2])}. Review before execution."
        else:
            return "Code appears safe based on static analysis."

    def _local_execution_explanation(
        self, scan_result: ScanResult, exec_result: ExecutionResult
    ) -> str:
        if exec_result.status == "success":
            return f"Code executed successfully in sandbox (exit code {exec_result.exit_code}) in {exec_result.execution_time:.2f}s."
        elif exec_result.status == "timeout":
            return "Execution timed out. The code may contain an infinite loop or heavy computation."
        elif exec_result.status == "error":
            stderr = exec_result.stderr[:200]
            return f"Runtime error: {stderr}. Check your code for logical issues."
        else:
            return "Unexpected execution outcome. Review logs for details."
