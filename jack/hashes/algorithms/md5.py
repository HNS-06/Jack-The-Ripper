"""MD5 hash algorithm implementation."""

import hashlib
import re
from typing import Optional
from .base import HashAlgorithm, HashInfo


class MD5Algorithm(HashAlgorithm):
    name = "MD5"
    format_id = "md5"
    hash_length = 32
    patterns = [
        r'^[a-f0-9]{32}$',
        r'^\$md5\$[a-f0-9]{32}$',
        r'^\$1\$[^\$]+\$[a-zA-Z0-9./]{22}$',  # md5crypt
    ]

    def identify(self, hash_str: str) -> float:
        cleaned = hash_str.strip()
        if re.match(r'^\$1\$', cleaned):
            return 0.95
        if re.match(r'^[a-fA-F0-9]{32}$', cleaned):
            return 0.7  # Ambiguous - could be other 32-char hex formats
        return 0.0

    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        if hash_info.salt:
            return self._verify_md5crypt(candidate, hash_info)
        return hashlib.md5(candidate.encode('utf-8')).hexdigest() == hash_info.hash_value.lower()

    def hash(self, password: str, salt: Optional[str] = None) -> str:
        if salt:
            return self._hash_md5crypt(password, salt)
        return hashlib.md5(password.encode('utf-8')).hexdigest()

    def _verify_md5crypt(self, candidate: str, hash_info: HashInfo) -> bool:
        import crypt
        try:
            return crypt.crypt(candidate, hash_info.original_line.strip()) == hash_info.original_line.strip()
        except Exception:
            return False

    def _hash_md5crypt(self, password: str, salt: str) -> str:
        import crypt
        return crypt.crypt(password, f"$1${salt}$")
