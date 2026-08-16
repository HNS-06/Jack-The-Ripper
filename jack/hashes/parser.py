"""Hash file parser supporting multiple input formats."""

from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
from .algorithms.base import HashInfo
from .detector import HashDetector


@dataclass
class ParseOptions:
    """Options for parsing hash files."""
    format_override: Optional[str] = None
    skip_empty: bool = True
    skip_comments: bool = True
    comment_char: str = '#'
    max_hashes: Optional[int] = None
    deduplicate: bool = True


class HashParser:
    """Parses hash files into structured hash information."""

    def __init__(self, detector: Optional[HashDetector] = None):
        self.detector = detector or HashDetector()

    def parse_file(self, filepath: str, options: Optional[ParseOptions] = None) -> List[HashInfo]:
        """Parse a hash file and return list of HashInfo objects."""
        options = options or ParseOptions()
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Hash file not found: {filepath}")

        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        return self._parse_lines(lines, options)

    def parse_string(self, content: str, options: Optional[ParseOptions] = None) -> List[HashInfo]:
        """Parse hash content from a string."""
        options = options or ParseOptions()
        lines = content.splitlines()
        return self._parse_lines(lines, options)

    def _parse_lines(self, lines: List[str], options: ParseOptions) -> List[HashInfo]:
        """Parse lines into HashInfo objects."""
        cleaned_lines = []

        for line in lines:
            line = line.strip()
            if options.skip_empty and not line:
                continue
            if options.skip_comments and line.startswith(options.comment_char):
                continue
            cleaned_lines.append(line)

        if options.max_hashes:
            cleaned_lines = cleaned_lines[:options.max_hashes]

        # Detect formats
        result = self.detector.detect_lines(cleaned_lines)

        # Apply format override if specified
        if options.format_override:
            algo = self.detector.registry.get(options.format_override)
            if algo:
                for hash_info in result.hash_infos:
                    hash_info.format_name = algo.name

        # Deduplicate if requested
        if options.deduplicate:
            seen = set()
            unique = []
            for hi in result.hash_infos:
                key = (hi.hash_value, hi.format_name)
                if key not in seen:
                    seen.add(key)
                    unique.append(hi)
            return unique

        return result.hash_infos

    def get_detection_summary(self, filepath: str) -> str:
        """Get a human-readable summary of hash detection."""
        result = self.detector.detect_file(filepath)

        lines = [
            "HASH IDENTIFICATION",
            "=" * 50,
            f"Input       : {result.input_file}",
            f"Total lines : {result.total_lines}",
            f"Valid hashes: {result.valid_hashes}",
            f"Unknown     : {result.unknown_count}",
            "",
            "Format Breakdown:",
        ]

        for fmt, count in sorted(result.format_breakdown.items(), key=lambda x: x[1], reverse=True):
            conf = result.confidence.get(fmt, 0)
            lines.append(f"  {fmt:20s} : {count:6d}  (confidence: {conf:.2f})")

        if result.ambiguous:
            lines.append("")
            lines.append("Ambiguous hashes:")
            for amb in result.ambiguous[:5]:
                lines.append(f"  {amb}")

        if result.unknown_count > 0:
            lines.append("")
            lines.append("Use --format to specify explicitly for unknown formats.")

        return "\n".join(lines)
