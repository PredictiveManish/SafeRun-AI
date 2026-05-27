"""
Database initialization and session management.
SQLAlchemy setup for SQLite.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.models import Base
from contextlib import contextmanager

_engine = None
_SessionLocal = None


def init_db(db_url: str = "sqlite:///./saferun.db"):
    """Initialize database engine and create tables.

    Safe to call multiple times - only creates engine once.
    """
    global _engine, _SessionLocal

    if _engine is None:
        _engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=False,  # Set to True for SQL debugging
        )

    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

    # Create all tables
    Base.metadata.create_all(bind=_engine)


def get_db():
    """FastAPI dependency for database sessions."""
    if _SessionLocal is None:
        init_db()  # Auto-initialize if needed

    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """Context manager for database sessions (for scripts/tests)."""
    if _SessionLocal is None:
        init_db()

    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
