"""SQLite database for persistent storage."""

import sqlite3
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager


class Database:
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path.home() / ".jack" / "jack.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    status TEXT, config TEXT, hash_file TEXT,
                    attack_mode TEXT, total_hashes INTEGER,
                    candidates_tested INTEGER, matches_found INTEGER,
                    created_at REAL, updated_at REAL,
                    started_at REAL, completed_at REAL, error TEXT
                );
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT, candidate TEXT, hash_value TEXT,
                    format_name TEXT, line_number INTEGER,
                    elapsed REAL, strategy TEXT, created_at REAL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE TABLE IF NOT EXISTS benchmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    format_name TEXT, speed REAL, duration INTEGER,
                    cpu_info TEXT, created_at REAL
                );
            """)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def save_session(self, session_data: dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sessions
                (session_id, status, config, hash_file, attack_mode,
                 total_hashes, candidates_tested, matches_found,
                 created_at, updated_at, started_at, completed_at, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_data.get("session_id"), session_data.get("status"),
                json.dumps(session_data.get("config", {})),
                session_data.get("hash_file"), session_data.get("attack_mode"),
                session_data.get("total_hashes", 0),
                session_data.get("candidates_tested", 0),
                session_data.get("matches_found", 0),
                session_data.get("created_at"), session_data.get("updated_at"),
                session_data.get("started_at"), session_data.get("completed_at"),
                session_data.get("error"),
            ))

    def save_match(self, session_id: str, match_data: dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO matches
                (session_id, candidate, hash_value, format_name,
                 line_number, elapsed, strategy, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, match_data.get("candidate"),
                match_data.get("hash_value"), match_data.get("format_name"),
                match_data.get("line_number"), match_data.get("elapsed"),
                match_data.get("strategy"), time.time(),
            ))

    def get_session(self, session_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_matches(self, session_id: str) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM matches WHERE session_id = ?", (session_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def list_sessions(self, limit: int = 50) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def save_benchmark(self, format_name: str, speed: float, duration: int, cpu_info: str = ""):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO benchmarks (format_name, speed, duration, cpu_info, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (format_name, speed, duration, cpu_info, time.time()))

    def get_benchmarks(self, format_name: Optional[str] = None) -> List[dict]:
        with self._connect() as conn:
            if format_name:
                rows = conn.execute(
                    "SELECT * FROM benchmarks WHERE format_name = ? ORDER BY created_at DESC",
                    (format_name,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM benchmarks ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]
