"""Report generation base."""

from typing import Optional, List
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass


@dataclass
class ReportData:
    session_id: str
    hash_file: str
    attack_mode: str
    format_detected: str
    total_hashes: int
    candidates_tested: int
    matches_found: int
    elapsed: float
    matches: List[dict]
    timestamp: float = 0.0

    @property
    def recovery_rate(self) -> float:
        if self.total_hashes > 0:
            return self.matches_found / self.total_hashes * 100
        return 0.0

    @property
    def speed(self) -> float:
        if self.elapsed > 0:
            return self.candidates_tested / self.elapsed
        return 0.0


class ReportGenerator:
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else Path.home() / ".jack" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, data: ReportData, filename: str) -> str:
        raise NotImplementedError

    def _default_filename(self, ext: str) -> str:
        return f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{ext}"
