"""
Database initialization and session management.
SQLAlchemy setup for SQLite.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.models import Base

_engine = None
_SessionLocal = None


def init_db(db_url: str = "sqlite:///./saferun.db"):
    """Initialize database engine and create tables."""
    global _engine, _SessionLocal
    _engine = create_engine(db_url, connect_args={"check_same_thread": False})
    _SessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=_engine
    )  # Fixed: was '-' now '='
    Base.metadata.create_all(bind=_engine)


def get_db() -> Session:
    """Dependency for FastAPI to get DB session."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
