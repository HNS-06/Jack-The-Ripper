"""Core candidate generation engine with streaming and deduplication."""

from typing import Iterator, Optional, Set, Callable, List
from dataclasses import dataclass, field
from collections import deque
import itertools
import hashlib


@dataclass
class GeneratorStats:
    """Statistics from candidate generation."""
    total_generated: int = 0
    duplicates_skipped: int = 0
    filtered_out: int = 0
    elapsed_seconds: float = 0.0
    
    @property
    def unique_candidates(self) -> int:
        return self.total_generated - self.duplicates_skipped
    
    @property
    def rate(self) -> float:
        if self.elapsed_seconds > 0:
            return self.unique_candidates / self.elapsed_seconds
        return 0.0


class CandidateGenerator:
    """Generates password candidates with streaming, deduplication, and filtering."""
    
    def __init__(
        self,
        max_candidates: Optional[int] = None,
        deduplicate: bool = True,
        min_length: int = 1,
        max_length: int = 64,
        charset_filter: Optional[str] = None,
    ):
        self.max_candidates = max_candidates
        self.deduplicate = deduplicate
        self.min_length = min_length
        self.max_length = max_length
        self.charset_filter = charset_filter
        self._seen: Set[str] = set()
        self._sources: List[Callable[[], Iterator[str]]] = []
        self._stats = GeneratorStats()
    
    def add_source(self, source_fn: Callable[[], Iterator[str]]):
        """Add a candidate source function."""
        self._sources.append(source_fn)
    
    def generate(self) -> Iterator[str]:
        """Generate candidates from all registered sources."""
        self._stats = GeneratorStats()
        self._seen.clear()
        count = 0
        
        for source_fn in self._sources:
            for candidate in source_fn():
                # Check max candidates
                if self.max_candidates and count >= self.max_candidates:
                    return
                
                # Length filter
                if len(candidate) < self.min_length or len(candidate) > self.max_length:
                    self._stats.filtered_out += 1
                    continue
                
                # Charset filter
                if self.charset_filter and not all(c in self.charset_filter for c in candidate):
                    self._stats.filtered_out += 1
                    continue
                
                # Deduplication
                if self.deduplicate:
                    candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
                    if candidate_hash in self._seen:
                        self._stats.duplicates_skipped += 1
                        continue
                    self._seen.add(candidate_hash)
                
                self._stats.total_generated += 1
                count += 1
                yield candidate
        
        self._stats.total_generated = count
    
    def generate_batch(self, batch_size: int = 1000) -> Iterator[List[str]]:
        """Generate candidates in batches."""
        batch = []
        for candidate in self.generate():
            batch.append(candidate)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch
    
    def get_stats(self) -> GeneratorStats:
        """Get generation statistics."""
        return self._stats
    
    def reset(self):
        """Reset the generator state."""
        self._seen.clear()
        self._stats = GeneratorStats()
