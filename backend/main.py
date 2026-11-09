"""
FastAPI application for SafeRun AI.
Provides endpoints for code scanning, execution, and history.
Serves static frontend at root.

Every endpoint that scans, executes or reads history requires an API key
(X-API-Key) -- see backend/auth.py. Bypassing the policy engine needs the
separate admin key (X-Admin-Key).
"""

import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.auth import require_admin_key, require_api_key
from backend.config import settings
from backend.database import init_db
from backend.schemas import (
    ScanRequest,
    ScanResponse,
    ExecuteRequest,
    ExecuteResponse,
    HistoryEntry,
    HealthResponse,
)
from backend.scanner import CodeScanner
from backend.policy_engine import PolicyEngine
from backend.sandbox import SandboxExecutor
from backend.audit import AuditStore
from backend.explanations import ExplanationGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global components
scanner = CodeScanner()
policy_engine = PolicyEngine(policy_path=settings.policy_file)
sandbox = SandboxExecutor(image_name=settings.sandbox_image)
audit_store = AuditStore(db_url=settings.database_url)
explanation_gen = ExplanationGenerator(api_key=settings.sarvam_api_key)

# Bounds how many containers can run at once. Each execution holds a slot for
# up to the policy timeout, so an unbounded number of callers could otherwise
# exhaust the host.
_exec_slots = threading.BoundedSemaphore(max(1, settings.max_concurrent_executions))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting SafeRun AI Backend...")
    init_db(settings.database_url)
    logger.info("Database initialized.")
    if not settings.api_key_list and not settings.allow_anonymous:
        logger.warning(
            "No SAFERUN_API_KEYS configured: /scan, /execute and /history will "
            "return 503 until a key is set."
        )
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="SafeRun AI Backend",
    description="Secure sandbox execution for AI-generated code",
    version="2.1.0",
    lifespan=lifespan,
)

# CORS is same-origin by default: the bundled frontend is served by this app.
# Set SAFERUN_ALLOWED_ORIGINS to a comma separated list if another site has to
# call the API. A wildcard is deliberately not available.
_allowed_origins = settings.allowed_origin_list
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key", "X-Admin-Key"],
    )


@app.get("/health", response_model=HealthResponse)
def health():
    """Health check endpoint (unauthenticated, returns no state)."""
    return HealthResponse(status="ok", service="SafeRun AI Backend")


@app.post("/scan", response_model=ScanResponse)
def scan_code(request: ScanRequest, _api_key: str = Depends(require_api_key)):
    """
    Perform static security scan on provided code without execution.
    Returns risk level, warnings, and detected patterns.
    """
    try:
        scan_result = scanner.scan(request.code)
        policy_violations = policy_engine.check_code(request.code, scan_result)
        blocked = scan_result.blocked or bool(policy_violations)
        explanation = explanation_gen.generate_scan_explanation(
            code=request.code,
            scan_result=scan_result,
            policy_violations=policy_violations,
        )
        return ScanResponse(
            risk_level=scan_result.risk_level,
            blocked=blocked,
            warnings=scan_result.warnings,
            detected_patterns=scan_result.detected_patterns,
            policy_violations=policy_violations,
            explanation=explanation,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Scan failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error while scanning",
        )


@app.post("/execute", response_model=ExecuteResponse)
def execute_code(
    request: ExecuteRequest,
    x_admin_key: Optional[str] = Header(default=None),
    _api_key: str = Depends(require_api_key),
):
    """
    Execute code in the sandbox after scanning and policy enforcement.

    If the code is blocked, execution is refused. Overriding that decision
    requires the admin key, not a client-supplied flag.
    """
    try:
        scan_result = scanner.scan(request.code)
        policy_violations = policy_engine.check_code(request.code, scan_result)
    except Exception:
        logger.exception("Scan failed before execution")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error while scanning",
        )

    blocked = scan_result.blocked or bool(policy_violations)

    if blocked and not request.override:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Execution blocked by security policy.",
        )
    if blocked and request.override:
        # Turning the policy engine off is an operator action, not a client
        # choice, so it needs the admin key rather than a request flag.
        require_admin_key(x_admin_key=x_admin_key)

    if not _exec_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many concurrent executions. Retry shortly.",
        )
    try:
        exec_result = sandbox.execute(
            code=request.code,
            timeout_seconds=policy_engine.get_max_execution_time(),
            memory_mb=policy_engine.get_max_memory_mb(),
            cpu_cores=policy_engine.get_max_cpu_cores(),
            network_enabled=policy_engine.get_network_enabled(),
            filesystem_write_enabled=policy_engine.get_filesystem_write_enabled(),
            max_output_bytes=policy_engine.get_max_output_bytes(),
        )
    except Exception:
        logger.exception("Sandbox execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Sandbox error",
        )
    finally:
        _exec_slots.release()

    try:
        audit_store.create_record(
            code=request.code,
            scan_risk_level=scan_result.risk_level,
            blocked=blocked,
            warnings=scan_result.warnings,
            stdout=exec_result.stdout,
            stderr=exec_result.stderr,
            exit_code=exec_result.exit_code,
            execution_time=exec_result.execution_time,
            status=exec_result.status,
        )
    except Exception:
        # Losing the audit row must not lose the result the caller waited for.
        logger.exception("Failed to write audit record")

    explanation = explanation_gen.generate_execution_explanation(
        code=request.code,
        scan_result=scan_result,
        exec_result=exec_result,
        policy_violations=policy_violations,
    )

    return ExecuteResponse(
        status=exec_result.status,
        risk_level=scan_result.risk_level,
        blocked=blocked,
        stdout=exec_result.stdout,
        stderr=exec_result.stderr,
        stdout_truncated=exec_result.stdout_truncated,
        stderr_truncated=exec_result.stderr_truncated,
        warnings=scan_result.warnings,
        execution_time=exec_result.execution_time,
        exit_code=exec_result.exit_code,
        container_status=exec_result.container_status,
        explanation=explanation,
    )


@app.get("/history", response_model=list[HistoryEntry])
def get_history(
    limit: int = Query(20, ge=1, le=200),
    _api_key: str = Depends(require_api_key),
):
    """Return last N execution records (max 200)."""
    return audit_store.get_recent(limit=limit)


# Serve static frontend files (must be after all API routes)
static_dir = Path(__file__).parent.parent / "frontend" / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
