"""Session management for audit persistence and resume."""

import json
import time
import uuid
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from ..attacks.base import AttackResult


@dataclass
class SessionData:
    """Persistent session data."""
    session_id: str
    status: str = "created"  # created, running, paused, completed, failed
    config: Dict[str, Any] = field(default_factory=dict)
    hash_file: str = ""
    format_detected: str = ""
    attack_mode: str = ""
    total_hashes: int = 0
    candidates_tested: int = 0
    matches_found: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    matches: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SessionData':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class SessionManager:
    """Manages audit sessions for persistence and resume."""
    
    def __init__(self, session_dir: Optional[str] = None):
        if session_dir:
            self.session_dir = Path(session_dir)
        else:
            self.session_dir = Path.home() / ".john" / "sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._current: Optional[SessionData] = None
    
    def create(self, config: dict = None) -> SessionData:
        """Create a new session."""
        session_id = f"audit-{time.strftime('%Y-%m-%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
        
        session = SessionData(
            session_id=session_id,
            status="created",
            config=config or {},
            created_at=time.time(),
            updated_at=time.time(),
        )
        
        self._current = session
        self._save(session)
        return session
    
    def get(self, session_id: str) -> Optional[SessionData]:
        """Get a session by ID."""
        session_file = self.session_dir / f"{session_id}.json"
        if session_file.exists():
            data = json.loads(session_file.read_text())
            return SessionData.from_dict(data)
        return None
    
    def list_sessions(self, limit: int = 20) -> List[SessionData]:
        """List recent sessions."""
        sessions = []
        for f in sorted(self.session_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            if len(sessions) >= limit:
                break
            data = json.loads(f.read_text())
            sessions.append(SessionData.from_dict(data))
        return sessions
    
    def update(self, session: SessionData):
        """Update session state."""
        session.updated_at = time.time()
        self._save(session)
        self._current = session
    
    def add_match(self, session: SessionData, match: AttackResult):
        """Add a match to the session."""
        session.matches.append(match.to_dict())
        session.matches_found = len(session.matches)
        self.update(session)
    
    def complete(self, session: SessionData):
        """Mark session as completed."""
        session.status = "completed"
        session.completed_at = time.time()
        self.update(session)
    
    def pause(self, session: SessionData):
        """Mark session as paused."""
        session.status = "paused"
        self.update(session)
    
    def delete(self, session_id: str):
        """Delete a session."""
        session_file = self.session_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()
    
    def _save(self, session: SessionData):
        """Save session to disk."""
        session_file = self.session_dir / f"{session.session_id}.json"
        session_file.write_text(json.dumps(session.to_dict(), indent=2))
    
    @property
    def current(self) -> Optional[SessionData]:
        return self._current
