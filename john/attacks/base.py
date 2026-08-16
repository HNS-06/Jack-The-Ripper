"""Base class for attack modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator, Optional, Dict, Any, Callable, List
import time


@dataclass
class AttackResult:
    """Result of an attack attempt."""
    candidate: str
    hash_value: str
    format_name: str
    line_number: int
    elapsed: float = 0.0
    strategy: str = ""
    
    def to_dict(self) -> dict:
        return {
            "candidate": self.candidate,
            "hash_value": self.hash_value,
            "format_name": self.format_name,
            "line_number": self.line_number,
            "elapsed": self.elapsed,
            "strategy": self.strategy,
        }


@dataclass
class AttackStats:
    """Statistics from an attack run."""
    total_tested: int = 0
    total_matches: int = 0
    elapsed_seconds: float = 0.0
    candidates_generated: int = 0
    
    @property
    def rate(self) -> float:
        if self.elapsed_seconds > 0:
            return self.total_tested / self.elapsed_seconds
        return 0.0
    
    @property
    def progress(self) -> float:
        if self.candidates_generated > 0:
            return self.total_tested / self.candidates_generated
        return 0.0


@dataclass
class AttackConfig:
    """Configuration for an attack."""
    mode: str = "dictionary"
    wordlist: Optional[str] = None
    mask: Optional[str] = None
    rules: Optional[str] = None
    max_candidates: Optional[int] = None
    max_time: Optional[int] = None  # seconds
    format_override: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class AttackBase(ABC):
    """Base class for all attack modules."""
    
    name: str = "base"
    description: str = "Base attack"
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self._stats = AttackStats()
        self._start_time = 0.0
        self._cancelled = False
        self._match_callback: Optional[Callable[[AttackResult], None]] = None
    
    def set_match_callback(self, callback: Callable[[AttackResult], None]):
        """Set callback for when a match is found."""
        self._match_callback = callback
    
    def cancel(self):
        """Cancel the attack."""
        self._cancelled = True
    
    @property
    def is_cancelled(self) -> bool:
        return self._cancelled
    
    @abstractmethod
    def generate_candidates(self) -> Iterator[str]:
        """Generate candidates for this attack."""
        pass
    
    def verify_candidate(
        self, 
        candidate: str, 
        hash_infos: list, 
        hash_engines: dict
    ) -> Optional[AttackResult]:
        """Verify a candidate against all hash infos."""
        for hash_info in hash_infos:
            algo = hash_engines.get(hash_info.format_name.lower())
            if not algo:
                continue
            
            start = time.time()
            try:
                if algo.verify(candidate, hash_info):
                    elapsed = time.time() - start
                    result = AttackResult(
                        candidate=candidate,
                        hash_value=hash_info.hash_value,
                        format_name=hash_info.format_name,
                        line_number=hash_info.line_number,
                        elapsed=elapsed,
                        strategy=self.name,
                    )
                    self._stats.total_matches += 1
                    if self._match_callback:
                        self._match_callback(result)
                    return result
            except Exception:
                continue
        
        return None
    
    def run(self, hash_infos: list, hash_engines: dict) -> AttackStats:
        """Execute the attack."""
        self._start_time = time.time()
        self._stats = AttackStats()
        self._cancelled = False
        
        for candidate in self.generate_candidates():
            if self._cancelled:
                break
            
            if self.config.max_time:
                elapsed = time.time() - self._start_time
                if elapsed >= self.config.max_time:
                    break
            
            self.verify_candidate(candidate, hash_infos, hash_engines)
            self._stats.total_tested += 1
        
        self._stats.elapsed_seconds = time.time() - self._start_time
        return self._stats
    
    def get_stats(self) -> AttackStats:
        return self._stats
