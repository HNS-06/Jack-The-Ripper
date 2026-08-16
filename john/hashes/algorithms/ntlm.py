"""NTLM hash algorithm implementation."""

import hashlib
import re
import struct
from typing import Optional
from .base import HashAlgorithm, HashInfo


def _md4(data: bytes) -> bytes:
    """Pure Python MD4 implementation for NTLM fallback."""
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def left_rotate(n, b): return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', msg_len * 8)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i+64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for k in [0,4,8,12]:
            a = left_rotate((a + F(b,c,d) + X[k]) & 0xFFFFFFFF, 3)
            d = left_rotate((d + F(a,b,c) + X[k+1]) & 0xFFFFFFFF, 7)
            c = left_rotate((c + F(d,a,b) + X[k+2]) & 0xFFFFFFFF, 11)
            b = left_rotate((b + F(c,d,a) + X[k+3]) & 0xFFFFFFFF, 19)
        # Round 2
        for k in [0,1,2,3]:
            a = left_rotate((a + G(b,c,d) + X[k] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = left_rotate((d + G(a,b,c) + X[k+4] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = left_rotate((c + G(d,a,b) + X[k+8] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = left_rotate((b + G(c,d,a) + X[k+12] + 0x5A827999) & 0xFFFFFFFF, 13)
        # Round 3
        for k in [0,2,1,3]:
            a = left_rotate((a + H(b,c,d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = left_rotate((d + H(a,b,c) + X[k+8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = left_rotate((c + H(d,a,b) + X[k+4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = left_rotate((b + H(c,d,a) + X[k+12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack('<4I', a, b, c, d)


class NTLMAlgorithm(HashAlgorithm):
    name = "NTLM"
    format_id = "ntlm"
    hash_length = 32
    patterns = [
        r'^[a-f0-9]{32}$',  # Same length as MD5 but context-dependent
        r'^\$NT\$[a-f0-9]{32}$',
        r'^[a-f0-9]{32}:[a-f0-9]{32}$',  # LM:NTLM format
    ]

    def identify(self, hash_str: str) -> float:
        cleaned = hash_str.strip()
        if cleaned.startswith('$NT$'):
            return 0.95
        if ':' in cleaned and re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$', cleaned):
            return 0.95
        # Plain 32-char hex is ambiguous with MD5
        if re.match(r'^[a-fA-F0-9]{32}$', cleaned):
            return 0.3
        return 0.0

    def _ntlm_hash(self, data: bytes) -> str:
        """Compute NTLM hash with fallback for systems without ntlm support."""
        try:
            return hashlib.new('ntlm', data).hexdigest()
        except (ValueError, AttributeError):
            return _md4(data).hex()

    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        ntlm_hash = self._ntlm_hash(candidate.encode('utf-16-le'))
        if not ntlm_hash:
            return False
        expected = hash_info.hash_value.lower()
        if ':' in expected:
            expected = expected.split(':')[1]
        return ntlm_hash == expected

    def hash(self, password: str, salt: Optional[str] = None) -> str:
        return self._ntlm_hash(password.encode('utf-16-le'))
