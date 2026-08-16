"""Session storage backend."""

from typing import Optional, List
from .database import Database
from ..core.session import SessionData


class SessionStorage:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def save(self, session: SessionData):
        self.db.save_session(session.to_dict())

    def load(self, session_id: str) -> Optional[SessionData]:
        data = self.db.get_session(session_id)
        if data:
            if isinstance(data.get("config"), str):
                import json
                data["config"] = json.loads(data["config"])
            return SessionData.from_dict(data)
        return None

    def list_recent(self, limit: int = 20) -> List[SessionData]:
        sessions = []
        for data in self.db.list_sessions(limit):
            if isinstance(data.get("config"), str):
                import json
                data["config"] = json.loads(data["config"])
            sessions.append(SessionData.from_dict(data))
        return sessions
