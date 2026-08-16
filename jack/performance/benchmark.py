"""Benchmarking subsystem."""

import time
from typing import Optional, List
from dataclasses import dataclass


@dataclass
class BenchmarkResult:
    algorithm: str
    speed: float
    duration: float
    total_hashes: int
    cpu_info: str = ""

    @property
    def speed_display(self) -> str:
        if self.speed >= 1_000_000:
            return f"{self.speed / 1_000_000:.2f} MH/s"
        elif self.speed >= 1_000:
            return f"{self.speed / 1_000:.2f} kH/s"
        return f"{self.speed:.0f} H/s"


class Benchmark:
    def __init__(self):
        self._results: List[BenchmarkResult] = []

    def run(self, algorithm, duration: int = 3, candidate_sample: str = "benchmark_sample") -> BenchmarkResult:
        start = time.time()
        count = 0
        while time.time() - start < duration:
            try:
                algorithm.hash(candidate_sample)
                count += 1
            except Exception:
                break
        elapsed = time.time() - start
        speed = count / elapsed if elapsed > 0 else 0
        result = BenchmarkResult(algorithm=algorithm.name, speed=speed, duration=elapsed, total_hashes=count)
        self._results.append(result)
        return result

    def run_all(self, registry, duration: int = 3) -> List[BenchmarkResult]:
        self._results.clear()
        for algo in registry.get_all_algorithms():
            try:
                self._results.append(self.run(algo, duration))
            except Exception:
                continue
        return self._results

    def get_results(self) -> List[BenchmarkResult]:
        return self._results

    def format_results(self) -> str:
        lines = [
            "BENCHMARK RESULTS",
            "=" * 50,
            f"{'Algorithm':<20} {'Speed':>15} {'Duration':>10}",
            "-" * 50,
        ]
        for r in self._results:
            lines.append(f"{r.algorithm:<20} {r.speed_display:>15} {r.duration:>8.1f}s")
        lines.append("=" * 50)
        return "\n".join(lines)
