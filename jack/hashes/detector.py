"""Hash format detection and analysis."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from collections import Counter
from .registry import HashFormatRegistry
from .algorithms.base import HashInfo


@dataclass
class DetectionResult:
    """Result of hash format detection."""
    input_file: str
    total_lines: int
    valid_hashes: int
    format_breakdown: Dict[str, int] = field(default_factory=dict)
    confidence: Dict[str, float] = field(default_factory=dict)
    ambiguous: List[str] = field(default_factory=list)
    unknown_count: int = 0
    hash_infos: List[HashInfo] = field(default_factory=list)

    @property
    def primary_format(self) -> Optional[str]:
        if not self.format_breakdown:
            return None
        return max(self.format_breakdown, key=self.format_breakdown.get)

    @property
    def is_uniform(self) -> bool:
        return len(self.format_breakdown) == 1


class HashDetector:
    """Detects and analyzes hash formats from input files."""

    def __init__(self, registry: Optional[HashFormatRegistry] = None):
        self.registry = registry or HashFormatRegistry()

    def detect_file(self, filepath: str) -> DetectionResult:
        """Detect hash formats in a file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Hash file not found: {filepath}")

        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        return self._analyze_lines(lines, str(path))

    def detect_lines(self, lines: List[str]) -> DetectionResult:
        """Detect hash formats from a list of lines."""
        return self._analyze_lines(lines, "<stdin>")

    def _analyze_lines(self, lines: List[str], source: str) -> DetectionResult:
        """Analyze a list of lines for hash formats."""
        result = DetectionResult(
            input_file=source,
            total_lines=len(lines),
            valid_hashes=0,
        )

        format_counts = Counter()
        format_confidence = Counter()

        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Try to identify the hash format
            candidates = self.registry.identify_hash(line)

            if candidates:
                best_algo, best_confidence = candidates[0]
                format_counts[best_algo.format_id] += 1
                format_confidence[best_algo.format_id] += best_confidence

                # Extract salt if applicable
                salt = self._extract_salt(line, best_algo.format_id)

                hash_info = HashInfo(
                    format_name=best_algo.name,
                    hash_value=best_algo._clean_hash(line),
                    original_line=line,
                    line_number=i,
                    salt=salt,
                )
                result.hash_infos.append(hash_info)
                result.valid_hashes += 1

                # Check for ambiguity
                if len(candidates) > 1 and candidates[1][1] > 0.5:
                    result.ambiguous.append(f"Line {i}: {line[:40]}...")
            else:
                result.unknown_count += 1

        # Calculate format breakdown and average confidence
        for fmt, count in format_counts.items():
            result.format_breakdown[fmt] = count
            result.confidence[fmt] = format_confidence[fmt] / count

        return result

    def _extract_salt(self, hash_str: str, format_id: str) -> Optional[str]:
        """Extract salt from a hash string if present."""
        import re

        # Unix crypt style: $id$salt$hash
        match = re.match(r'^\$[^$]+\$([^$]+)\$', hash_str)
        if match:
            return match.group(1)

        # SHA1 with salt: sha1$salt$hash
        match = re.match(r'^sha1\$([^$]+)\$', hash_str)
        if match:
            return match.group(1)

        return None

    def get_supported_formats(self) -> List[dict]:
        """List all supported hash formats."""
        return self.registry.list_formats()
