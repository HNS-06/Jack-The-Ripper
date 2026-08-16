"""SHA-256 hash algorithm implementation."""

import hashlib
import re
from typing import Optional
from .base import HashAlgorithm, HashInfo


class SHA256Algorithm(HashAlgorithm):
    name = "SHA-256"
    format_id = "sha256"
    hash_length = 64
    patterns = [
        r'^[a-f0-9]{64}$',
        r'^\$5\$[^\$]+\$[a-zA-Z0-9./]{43}$',
        r'^\$sha256\$[a-f0-9]+\$[a-f0-9]+$',
    ]

    def identify(self, hash_str: str) -> float:
        cleaned = hash_str.strip()
        if cleaned.startswith('$5$'):
            return 0.95
        if cleaned.startswith('$sha256$'):
            return 0.95
        if re.match(r'^[a-fA-F0-9]{64}$', cleaned):
            return 0.5
        return 0.0

    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        if hash_info.original_line.startswith('$5$'):
            return self._verify_sha256crypt(candidate, hash_info)
        return hashlib.sha256(candidate.encode('utf-8')).hexdigest() == hash_info.hash_value.lower()

    def hash(self, password: str, salt: Optional[str] = None) -> str:
        if salt:
            return self._hash_sha256crypt(password, salt)
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def _verify_sha256crypt(self, candidate: str, hash_info: HashInfo) -> bool:
        import crypt
        try:
            return crypt.crypt(candidate, hash_info.original_line.strip()) == hash_info.original_line.strip()
        except Exception:
            return False

    def _hash_sha256crypt(self, password: str, salt: str) -> str:
        import crypt
        return crypt.crypt(password, f"$5${salt}$")
