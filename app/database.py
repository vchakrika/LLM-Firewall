"""SQLite telemetry. One row per request that passes through the gateway."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.config import DB_PATH, PROMPT_SNIPPET_CHARS


def _connect() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    """Create the schema. Called once at app startup (not at import time)."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                prompt_snippet TEXT,
                status TEXT,
                reason TEXT,
                latency_ms REAL
            )
        """)


def log_telemetry(prompt: str, status: str, reason: str, latency_ms: float) -> None:
    """Log a single traffic event. Blocking call: main.py runs it in a worker thread."""
    conn = _connect()
    try:
        with conn:  # commits on success, rolls back on error
            conn.execute(
                "INSERT INTO telemetry (timestamp, prompt_snippet, status, reason, latency_ms) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    prompt[:PROMPT_SNIPPET_CHARS] if prompt else "",
                    status,
                    reason,
                    round(latency_ms, 2),
                ),
            )
    finally:
        conn.close()
