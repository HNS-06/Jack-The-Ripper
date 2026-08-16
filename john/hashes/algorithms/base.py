"""Base class for hash algorithm implementations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import hashlib
import re


@dataclass
class HashInfo:
    """Information about a detected hash."""
    format_name: str
    hash_value: str
    original_line: str
    line_number: int = 0
    salt: Optional[str] = None
    extra: dict = field(default_factory=dict)


class HashAlgorithm(ABC):
    """Base class for all hash algorithms."""

    name: str = "unknown"
    format_id: str = "unknown"
    hash_length: int = 0
    salt_separator: str = "$"
    patterns: list[str] = []

    @abstractmethod
    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        """Verify a candidate against a hash."""
        pass

    @abstractmethod
    def identify(self, hash_str: str) -> float:
        """Return confidence (0-1) that this hash matches this format."""
        pass

    @abstractmethod
    def hash(self, password: str, salt: Optional[str] = None) -> str:
        """Generate a hash from a password."""
        pass

    def _clean_hash(self, hash_str: str) -> str:
        """Remove format identifiers from hash string."""
        cleaned = hash_str.strip()
        for prefix in [f"${self.format_id}$", f"{self.format_id}$"]:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
                break
        return cleaned
