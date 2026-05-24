"""
Audit storage using SQLAlchemy.
Provides methods to create and retrieve execution records.
"""

import hashlib
import json
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.database import init_db, get_db
from backend.models import ExecutionRecord


class AuditStore:
    """Handles storage of execution history."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        # Ensure DB initialized
        init_db(db_url)
        self._session = None

    def _get_session(self) -> Session:
        """Get a new session (simple approach, not for concurrent heavy use)."""
        from backend.database import _SessionLocal

        if _SessionLocal is None:
            init_db(self.db_url)
        return _SessionLocal()

    def create_record(
        self,
        code: str,
        scan_risk_level: str,
        blocked: bool,
        warnings: List[str],
        stdout: str,
        stderr: str,
        exit_code: Optional[int],
        execution_time: float,
        status: str,
    ) -> ExecutionRecord:
        """Create and store an execution record."""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        warnings_json = json.dumps(warnings)

        record = ExecutionRecord(
            code_hash=code_hash,
            risk_level=scan_risk_level,
            blocked=1 if blocked else 0,
            warnings=warnings_json,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            execution_time=execution_time,
            status=status,
        )
        session = self._get_session()
        try:
            session.add(record)
            session.commit()
            session.refresh(record)
            return record
        finally:
            session.close()

    def get_recent(self, limit: int = 20) -> List[dict]:
        """Return last N records as dicts."""
        session = self._get_session()
        try:
            records = (
                session.query(ExecutionRecord)
                .order_by(ExecutionRecord.id.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dict() for r in records]
        finally:
            session.close()
