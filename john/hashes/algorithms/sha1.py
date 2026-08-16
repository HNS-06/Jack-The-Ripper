"""SHA-1 hash algorithm implementation."""

import hashlib
import re
from typing import Optional
from .base import HashAlgorithm, HashInfo


class SHA1Algorithm(HashAlgorithm):
    name = "SHA-1"
    format_id = "sha1"
    hash_length = 40
    patterns = [
        r'^[a-f0-9]{40}$',
        r'^\{SHA\}[a-zA-Z0-9+/]+=*$',
        r'^sha1\$[a-f0-9]+\$[a-f0-9]+$',
    ]

    def identify(self, hash_str: str) -> float:
        cleaned = hash_str.strip()
        if cleaned.startswith('{SHA}'):
            return 0.95
        if re.match(r'^sha1\$', cleaned):
            return 0.95
        if re.match(r'^[a-fA-F0-9]{40}$', cleaned):
            return 0.6
        return 0.0

    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        if hash_info.original_line.startswith('{SHA}'):
            import base64
            expected = base64.b64decode(hash_info.hash_value.replace('{SHA}', '')).hex()
            return hashlib.sha1(candidate.encode('utf-8')).hexdigest() == expected
        return hashlib.sha1(candidate.encode('utf-8')).hexdigest() == hash_info.hash_value.lower()

    def hash(self, password: str, salt: Optional[str] = None) -> str:
        return hashlib.sha1(password.encode('utf-8')).hexdigest()
