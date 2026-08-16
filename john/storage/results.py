"""Result storage and management."""

import json
import time
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, asdict


@dataclass
class StoredResult:
    target_id: str
    format: str
    status: str
    candidate: Optional[str] = None
    strategy: str = ""
    elapsed: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


class ResultStore:
    def __init__(self, store_dir: Optional[str] = None):
        self.store_dir = Path(store_dir) if store_dir else Path.home() / ".john" / "results"
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def save(self, session_id: str, results: List[dict]):
        output_file = self.store_dir / f"{session_id}.json"
        data = {"session_id": session_id, "timestamp": time.time(), "results": results}
        output_file.write_text(json.dumps(data, indent=2))

    def load(self, session_id: str) -> Optional[dict]:
        output_file = self.store_dir / f"{session_id}.json"
        if output_file.exists():
            return json.loads(output_file.read_text())
        return None

    def list_results(self) -> List[dict]:
        results = []
        for f in sorted(self.store_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            data = json.loads(f.read_text())
            results.append({
                "session_id": data.get("session_id"),
                "timestamp": data.get("timestamp"),
                "match_count": len(data.get("results", [])),
            })
        return results

    def delete(self, session_id: str):
        output_file = self.store_dir / f"{session_id}.json"
        if output_file.exists():
            output_file.unlink()
