"""Performance metrics collection and reporting."""

import time
from dataclasses import dataclass, field


@dataclass
class Metrics:
    start_time: float = 0.0
    candidates_tested: int = 0
    matches_found: int = 0
    errors: int = 0
    _snapshots: list = field(default_factory=list)

    def start(self):
        self.start_time = time.time()

    def record_test(self, count: int = 1):
        self.candidates_tested += count

    def record_match(self):
        self.matches_found += 1

    def record_error(self):
        self.errors += 1

    def snapshot(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        self._snapshots.append({
            "time": elapsed, "tested": self.candidates_tested,
            "matches": self.matches_found,
            "rate": self.candidates_tested / elapsed if elapsed > 0 else 0,
        })

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0

    @property
    def rate(self) -> float:
        return self.candidates_tested / self.elapsed if self.elapsed > 0 else 0.0

    def summary(self) -> dict:
        return {
            "elapsed": self.elapsed,
            "candidates_tested": self.candidates_tested,
            "matches_found": self.matches_found,
            "errors": self.errors,
            "rate": self.rate,
        }
