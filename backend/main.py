"""
FastAPI application for SafeRun AI.
Provides endpoints for code scanning, execution, and history.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.config import Settings
from backend.database import init_db, SessionLocal
from backend.schemas import (
    ScanRequest,
    ScanResponse,
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
