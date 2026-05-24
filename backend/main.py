"""
FastAPI application for SafeRun AI.
Provides endpoints for code scanning, execution, and history.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import init_db
from backend.schemas import (
    ScanRequest,
    ScanResponse,
    ExecuteRequest,
    ExecuteResponse,
    HistoryEntry,
    HealthResponse,
    InfoResponse,
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting SafeRun AI Backend...")
    init_db()
    logger.info("Database initialized.")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="SafeRun AI Backend",
    description="Secure sandbox execution for AI-generated code",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for Streamlit frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=InfoResponse)
async def root():
    """Basic API information."""
    return InfoResponse(
        name="SafeRun AI API",
        version="1.0.0",
        description="Secure sandbox execution for AI-generated code",
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(status="ok", service="SafeRun AI Backend")


@app.post("/scan", response_model=ScanResponse)
async def scan_code(request: ScanRequest):
    """
    Perform static security scan on provided code without execution.
    Returns risk level, warnings, and detected patterns.
    """
    try:
        # Run scanner
        scan_result = scanner.scan(request.code)

        # Check policy violations
        policy_violations = policy_engine.check_code(request.code, scan_result)

        # Determine overall risk and blocked status
        blocked = scan_result.blocked or bool(policy_violations)

        # Generate explanation (local or AI)
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
    except Exception as e:
        logger.exception("Scan failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanning error: {str(e)}",
        )


@app.post("/execute", response_model=ExecuteResponse)
async def execute_code(request: ExecuteRequest):
    """
    Execute code in sandbox after scanning and policy enforcement.
    If blocked and override=False, refuses execution.
    """
    # Step 1: Scan
    scan_result = scanner.scan(request.code)
    policy_violations = policy_engine.check_code(request.code, scan_result)

    blocked = scan_result.blocked or bool(policy_violations)

    # Step 2: If blocked and no override, reject
    if blocked and not request.override:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Execution blocked by security policy. Use override=true at your own risk.",
        )

    # Step 3: Execute in sandbox
    try:
        exec_result = sandbox.execute(
            code=request.code,
            timeout_seconds=policy_engine.get_max_execution_time(),
            memory_mb=policy_engine.get_max_memory_mb(),
            cpu_cores=policy_engine.get_max_cpu_cores(),
            network_enabled=policy_engine.get_network_enabled(),
            filesystem_write_enabled=policy_engine.get_filesystem_write_enabled(),
        )
    except Exception as e:
        logger.exception("Sandbox execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sandbox error: {str(e)}",
        )

    # Step 4: Store audit record
    audit_record = audit_store.create_record(
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

    # Step 5: Generate explanation (if needed)
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
        warnings=scan_result.warnings,
        execution_time=exec_result.execution_time,
        exit_code=exec_result.exit_code,
        container_status=exec_result.container_status,
        explanation=explanation,
    )


@app.get("/history", response_model=list[HistoryEntry])
async def get_history(limit: int = 20):
    """Return last N execution records."""
    records = audit_store.get_recent(limit=limit)
    return records

