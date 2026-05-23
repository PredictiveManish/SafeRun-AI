"""
SQLAlchemy ORM models for audit storage.
"""

from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class ExecutionRecord(Base):
    """Store execution audit records."""

    __tablename__ = "executions"

    id = Column(Integer, primary_key=True, index=True)
    code_hash = Column(String(64), nullable=False, index=True)
    risk_level = Column(String(20), nullable=False)
    blocked = Column(Integer, default=0)  # Sqlite boolean as int
    warnings = Column(Text, default="")  # JSON string
    stdout = Column(Text, default="")
    exit_code = Column(Integer, default=True)
    execution_time = Column(Float, default=0.0)
    status = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "code_hash": self.code_hash,
            "risk_level": self.risk_level,
            "blocked": bool(self.blocked),
            "warnings": self.warnings,
            "stdout": self.stdout,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }
