"""SHA-512 hash algorithm implementation."""

import hashlib
import re
from typing import Optional
from .base import HashAlgorithm, HashInfo


class SHA512Algorithm(HashAlgorithm):
    name = "SHA-512"
    format_id = "sha512"
    hash_length = 128
    patterns = [
        r'^[a-f0-9]{128}$',
        r'^\$6\$[^\$]+\$[a-zA-Z0-9./]{86}$',
        r'^\$sha512\$[a-f0-9]+\$[a-f0-9]+$',
    ]

    def identify(self, hash_str: str) -> float:
        cleaned = hash_str.strip()
        if cleaned.startswith('$6$'):
            return 0.95
        if cleaned.startswith('$sha512$'):
            return 0.95
        if re.match(r'^[a-fA-F0-9]{128}$', cleaned):
            return 0.5
        return 0.0

    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        if hash_info.original_line.startswith('$6$'):
            return self._verify_sha512crypt(candidate, hash_info)
        return hashlib.sha512(candidate.encode('utf-8')).hexdigest() == hash_info.hash_value.lower()

    def hash(self, password: str, salt: Optional[str] = None) -> str:
        if salt:
            return self._hash_sha512crypt(password, salt)
        return hashlib.sha512(password.encode('utf-8')).hexdigest()

    def _verify_sha512crypt(self, candidate: str, hash_info: HashInfo) -> bool:
        import crypt
        try:
            return crypt.crypt(candidate, hash_info.original_line.strip()) == hash_info.original_line.strip()
        except Exception:
            return False

    def _hash_sha512crypt(self, password: str, salt: str) -> str:
        import crypt
        return crypt.crypt(password, f"$6${salt}$")
