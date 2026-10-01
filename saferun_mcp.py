"""
SafeRun AI — MCP Server
=======================

Exposes SafeRun as Model Context Protocol (MCP) tools so that any
MCP-capable agent client (Claude Desktop / Code, Cursor, VS Code Copilot,
Claude Code CLI, or your own agent built on any MCP-compatible framework)
can use SafeRun's sandbox as its secure Python code-execution tool.

The agent never runs code on the host directly — every snippet goes
through the full SafeRun pipeline:

    AST scan -> YAML policy check -> Docker sandbox -> audit log

Run it:
    pip install mcp docker pyyaml sqlalchemy
    python saferun_mcp.py            # stdio transport (what MCP clients expect)
    # (works with both mcp SDK v1 and v2)

Register it with an MCP client (example, Claude Desktop / Cursor config):

    {
      "mcpServers": {
        "saferun": {
          "command": "python",
          "args": ["/absolute/path/to/saferun_mcp.py"]
        }
      }
    }
"""

import json
import logging
from pathlib import Path

# The MCP Python SDK renamed FastMCP to MCPServer in v2 (same API
# surface: @server.tool(), server.run(), list_tools, call_tool).
try:
    from mcp.server.fastmcp import FastMCP as _ServerBase  # mcp SDK v1
except ImportError:  # mcp SDK v2+
    from mcp.server.mcpserver import MCPServer as _ServerBase

# --- SafeRun backend components (same composition as backend/main.py) ------
from backend.scanner import CodeScanner
from backend.policy_engine import PolicyEngine
from backend.sandbox import SandboxExecutor
from backend.audit import AuditStore
from backend.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("saferun.mcp")

REPO_ROOT = Path(__file__).resolve().parent

mcp = _ServerBase("saferun")

# Resolve paths relative to this file so the server works from any cwd.
_POLICY_FILE = Path(settings.policy_file)
if not _POLICY_FILE.is_absolute():
    _POLICY_FILE = REPO_ROOT / _POLICY_FILE

scanner = CodeScanner()
policy_engine = PolicyEngine(policy_path=str(_POLICY_FILE))
sandbox = SandboxExecutor(image_name=settings.sandbox_image)
audit_store = AuditStore(db_url=settings.database_url)


@mcp.tool()
def scan_code(code: str) -> str:
    """Statically scan a Python snippet for security risks WITHOUT executing it.

    Use this first when you want to check whether code is safe to run.
    Returns a JSON object with:
      - risk_level: LOW, MEDIUM, HIGH, or BLOCKED
      - blocked: whether execution would be refused
      - warnings: human-readable list of findings
      - policy_violations: list of violated policy rules (if any)

    Never executes anything. Safe to call on any snippet.
    """
    scan_result = scanner.scan(code)
    violations = policy_engine.check_code(code, scan_result)
    return json.dumps(
        {
            "risk_level": scan_result.risk_level,
            "blocked": scan_result.blocked or bool(violations),
            "warnings": scan_result.warnings,
            "detected_patterns": scan_result.detected_patterns,
            "policy_violations": violations,
        },
        indent=2,
    )


@mcp.tool()
def execute_code(code: str, timeout_seconds: int = 10) -> str:
    """Execute a Python snippet inside SafeRun's hardened Docker sandbox.

    This is the ONLY way to run Python code — never use shell commands,
    file writes, or any other execution mechanism to run code.
    The snippet is first statically scanned, then checked against the
    security policy, and only then executed in an isolated container
    (no network, read-only root filesystem, resource limits).

    Args:
        code: The Python source code to execute. Must print any results
              to stdout — the sandbox captures stdout/stderr and returns them.
        timeout_seconds: Execution time limit (default 10, max per policy).

    Returns a JSON object with:
      - status: "success", "timeout", or "error"
      - stdout / stderr: captured output
      - exit_code and execution_time
    If the code is blocked by the security policy, the call returns a
    refusal with the reasons instead of executing.
    """
    scan_result = scanner.scan(code)
    violations = policy_engine.check_code(code, scan_result)

    if scan_result.blocked or violations:
        return json.dumps(
            {
                "status": "refused",
                "reason": "Code was blocked by SafeRun security policy.",
                "risk_level": scan_result.risk_level,
                "warnings": scan_result.warnings,
                "policy_violations": violations,
            },
            indent=2,
        )

    exec_result = sandbox.execute(
        code=code,
        timeout_seconds=timeout_seconds,
        memory_mb=policy_engine.get_max_memory_mb(),
        cpu_cores=policy_engine.get_max_cpu_cores(),
        network_enabled=policy_engine.get_network_enabled(),
        filesystem_write_enabled=policy_engine.get_filesystem_write_enabled(),
    )

    audit_store.create_record(
        code=code,
        scan_risk_level=scan_result.risk_level,
        blocked=False,
        warnings=scan_result.warnings,
        stdout=exec_result.stdout,
        stderr=exec_result.stderr,
        exit_code=exec_result.exit_code,
        execution_time=exec_result.execution_time,
        status=exec_result.status,
    )

    return json.dumps(
        {
            "status": exec_result.status,
            "stdout": exec_result.stdout,
            "stderr": exec_result.stderr,
            "exit_code": exec_result.exit_code,
            "execution_time": round(exec_result.execution_time, 2),
            "container_status": exec_result.container_status,
        },
        indent=2,
    )


@mcp.tool()
def get_history(limit: int = 20) -> str:
    """Return the most recent sandbox executions from the SafeRun audit log.

    Each entry contains the code, scan risk level, exit code, execution
    status, and duration. Useful for reviewing what was run recently.
    """
    records = audit_store.get_recent(limit=limit)
    return json.dumps(
        [
            {
                "id": r["id"],
                "timestamp": r["created_at"],
                "risk_level": r["risk_level"],
                "status": r["status"],
                "exit_code": r["exit_code"],
                "execution_time": r["execution_time"],
                "code_hash": r["code_hash"],
            }
            for r in records
        ],
        indent=2,
    )


if __name__ == "__main__":
    mcp.run()  # stdio transport — the default for MCP clients
