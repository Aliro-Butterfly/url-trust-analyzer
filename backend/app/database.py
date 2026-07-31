from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

from .config import DB_BUSY_TIMEOUT_MS, get_db_path

_write_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode allows concurrent reads alongside one writer
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT_MS}")
    return conn


from .crypto import decrypt_api_key, encrypt_api_key


def initialize_database() -> None:
    with _write_lock:
        # Use direct connection (not context manager) to control DDL commits precisely.
        conn = get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    url TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    confidence INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    processing_time_ms INTEGER,
                    providers_count INTEGER,
                    algo_version TEXT,
                    from_cache INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    provider TEXT NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, provider)
                )
            """)
            conn.commit()  # Commit CREATE TABLE statements before ALTER TABLE migrations

            # Safe migrations — each committed individually to avoid transaction rollback
            _add_column_if_missing(conn, "history", "user_id", "INTEGER")
            _add_column_if_missing(conn, "history", "processing_time_ms", "INTEGER")
            _add_column_if_missing(conn, "history", "providers_count", "INTEGER")
            _add_column_if_missing(conn, "history", "algo_version", "TEXT")
            _add_column_if_missing(conn, "history", "from_cache", "INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        finally:
            conn.close()
def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    existing = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def save_analysis(
    report: dict[str, Any],
    username: str,
    *,
    processing_time_ms: int | None = None,
    providers_count: int | None = None,
    algo_version: str | None = None,
    from_cache: bool = False,
) -> None:
    with _write_lock:
        with get_connection() as conn:
            user_row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user_row:
                return
            conn.execute(
                """INSERT INTO history
                   (user_id, url, overall_score, confidence, payload, created_at,
                    processing_time_ms, providers_count, algo_version, from_cache)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user_row["id"],
                    report["url"],
                    report["overall_score"],
                    report["confidence"],
                    json.dumps(report, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                    processing_time_ms,
                    providers_count,
                    algo_version,
                    int(from_cache),
                ),
            )
            conn.commit()


def create_user(username: str, password_hash: str) -> None:
    with _write_lock:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()


def get_user_by_username(username: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None


def save_api_key(username: str, provider: str, api_key: str | None) -> None:
    user_row = get_user_by_username(username)
    if not user_row:
        return
    with _write_lock:
        with get_connection() as conn:
            if not api_key:
                conn.execute(
                    "DELETE FROM api_keys WHERE user_id = ? AND provider = ?",
                    (user_row["id"], provider),
                )
            else:
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """INSERT INTO api_keys
                       (user_id, provider, encrypted_key, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(user_id, provider)
                       DO UPDATE SET encrypted_key = excluded.encrypted_key,
                                     updated_at = excluded.updated_at""",
                    (user_row["id"], provider, encrypt_api_key(api_key), now, now),
                )
            conn.commit()


def fetch_api_keys(username: str) -> dict[str, str]:
    user_row = get_user_by_username(username)
    if not user_row:
        return {}
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT provider, encrypted_key FROM api_keys WHERE user_id = ?",
            (user_row["id"],),
        ).fetchall()
    return {
        row["provider"]: dec
        for row in rows
        if (dec := decrypt_api_key(row["encrypted_key"])) is not None
    }


def fetch_history(
    limit: int | None = None,
    username: str | None = None,
) -> list[dict[str, Any]]:
    from .config import HISTORY_DEFAULT_LIMIT
    effective_limit = limit if limit is not None else HISTORY_DEFAULT_LIMIT

    with get_connection() as conn:
        if username:
            user_row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user_row:
                return []
            rows = conn.execute(
                """SELECT id, url, overall_score, confidence, payload, created_at,
                          processing_time_ms, providers_count, algo_version, from_cache
                   FROM history WHERE user_id = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (user_row["id"], effective_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, url, overall_score, confidence, payload, created_at,
                          processing_time_ms, providers_count, algo_version, from_cache
                   FROM history ORDER BY created_at DESC LIMIT ?""",
                (effective_limit,),
            ).fetchall()

        return [
            {
                "id": row["id"],
                "url": row["url"],
                "overall_score": row["overall_score"],
                "confidence": row["confidence"],
                "created_at": row["created_at"],
                "processing_time_ms": row["processing_time_ms"],
                "providers_count": row["providers_count"],
                "algo_version": row["algo_version"],
                "from_cache": bool(row["from_cache"]),
                "report": json.loads(row["payload"]),
            }
            for row in rows
        ]