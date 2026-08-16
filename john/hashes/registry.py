"""Hash format registry for managing algorithm implementations."""

from typing import Optional, Dict, List, Type
from .algorithms.base import HashAlgorithm, HashInfo
from .algorithms.md5 import MD5Algorithm
from .algorithms.sha1 import SHA1Algorithm
from .algorithms.sha256 import SHA256Algorithm
from .algorithms.sha512 import SHA512Algorithm
from .algorithms.ntlm import NTLMAlgorithm
from .algorithms.bcrypt import BcryptAlgorithm


class HashFormatRegistry:
    """Registry of all supported hash formats."""

    def __init__(self):
        self._algorithms: Dict[str, HashAlgorithm] = {}
        self._register_builtins()

    def _register_builtins(self):
        """Register all built-in hash algorithms."""
        builtins = [
            MD5Algorithm(),
            SHA1Algorithm(),
            SHA256Algorithm(),
            SHA512Algorithm(),
            NTLMAlgorithm(),
            BcryptAlgorithm(),
        ]
        for algo in builtins:
            self.register(algo)

    def register(self, algorithm: HashAlgorithm):
        """Register a hash algorithm."""
        self._algorithms[algorithm.format_id] = algorithm

    def get(self, format_id: str) -> Optional[HashAlgorithm]:
        """Get algorithm by format ID."""
        return self._algorithms.get(format_id)

    def list_formats(self) -> List[dict]:
        """List all registered formats."""
        return [
            {
                "id": algo.format_id,
                "name": algo.name,
                "hash_length": algo.hash_length,
                "patterns": len(algo.patterns),
            }
            for algo in self._algorithms.values()
        ]

    def identify_hash(self, hash_str: str) -> List[tuple]:
        """Identify possible formats for a hash string.

        Returns list of (algorithm, confidence) tuples sorted by confidence.
        """
        results = []
        for algo in self._algorithms.values():
            confidence = algo.identify(hash_str)
            if confidence > 0:
                results.append((algo, confidence))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def get_all_algorithms(self) -> List[HashAlgorithm]:
        """Get all registered algorithms."""
        return list(self._algorithms.values())
