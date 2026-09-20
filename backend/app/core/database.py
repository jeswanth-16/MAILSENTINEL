import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional

from app.core.config import settings
from app.core.logging import logger


def get_db_path(custom_path: Optional[str] = None) -> str:
    """
    Resolves the SQLite database file path.
    Precedence: custom_path argument -> MAILSENTINEL_DB_PATH env var -> settings.MAILSENTINEL_DB_PATH.
    """
    if custom_path:
        return custom_path
    return os.environ.get("MAILSENTINEL_DB_PATH", settings.MAILSENTINEL_DB_PATH)


@contextmanager
def get_db_connection(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for SQLite connections with thread safety, WAL mode,
    row dictionary conversion, and robust transaction management.
    """
    path = get_db_path(db_path)
    
    # Ensure directory exists if not an in-memory database
    if path != ":memory:":
        dir_name = os.path.dirname(os.path.abspath(path))
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

    conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Enable WAL mode and normal synchronous for fast concurrent reads and safe writes
    if path != ":memory:":
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.DatabaseError:
            pass
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes the SQLite database tables and indexes if they do not already exist.
    Safe to call multiple times. Preserves existing data.
    """
    path = get_db_path(db_path)
    logger.info(f"Initializing MAILSENTINEL SQLite database at: {path}")

    with get_db_connection(path) as conn:
        # Table 1: investigations
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                case_number TEXT,
                title TEXT,
                status TEXT,
                severity TEXT,
                classification TEXT,
                risk_score INTEGER DEFAULT 0,
                data TEXT NOT NULL,
                forensic_data TEXT,
                threat_data TEXT,
                intel_data TEXT,
                evidence_package_data TEXT,
                custody_data TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT
            );
        """)

        # Table 2: cases
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                investigation_id TEXT,
                title TEXT,
                status TEXT,
                priority TEXT,
                verdict TEXT,
                assigned_analyst TEXT,
                risk_score INTEGER DEFAULT 0,
                data TEXT NOT NULL,
                audit_logs TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT
            );
        """)

        # Table 3: assessments
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                evidence_hash TEXT,
                engine_version TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT
            );
        """)

        # Performance indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_investigation_id ON cases(investigation_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_investigation_id ON assessments(investigation_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_verdict ON assessments(verdict);")

    logger.info("MAILSENTINEL SQLite tables and indexes initialized successfully.")
