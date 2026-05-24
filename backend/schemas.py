"""Pydantic schemes for API request/response validation."""

from typing import List, Optional
from pydantic import BaseModel


class CodeRequest(BaseModel):
    code: str


# /scan
class ScanRequest(BaseModel):
    code: str


class ScanResponse(BaseModel):
    risk_level: str  # LOW, MEDIUM, HIGH, BLOCKED
    blocked: bool
    warnings: List[str]
    detected_patterns: List[str]
    policy_violations: List[str]
    explanation: str


# /execute
class ExecuteRequest(BaseModel):
    code: str
    override: bool = False


class ExecuteResponse(BaseModel):
    status: str  # success, timeout, error, killed
    risk_level: str
    blocked: bool
    stdout: str
    stderr: str
    warnings: List[str]
    execution_time: float
    exit_code: Optional[int]
    container_status: str
    explanation: str


# /history
class HistoryEntry(BaseModel):
    id: int
    code_hash: str
    risk_level: str
    blocked: bool
    warnings: str  # JSON string
    stdout: str
    stderr: str
    exit_code: Optional[int]
    execution_time: float
    status: str
    created_at: str


# /health
class HealthResponse(BaseModel):
    status: str
    service: str


# /Info
class InfoResponse(BaseModel):
    name: str
    version: str
    description: str
