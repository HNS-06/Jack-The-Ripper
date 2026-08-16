"""Incremental (smart brute force) attack - auto-iterates charset combinations."""

from typing import Iterator, Optional
import itertools
from .base import AttackBase, AttackConfig


CHARSETS = {
    "digits": "0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alphanum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "printable": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~ ",
    "hex": "0123456789abcdef",
}


class IncrementalAttack(AttackBase):
    """Incremental attack that auto-iterates from short to long candidates."""
    
    name = "incremental"
    description = "Smart brute force with automatic length progression"
    
    def __init__(self, config: AttackConfig):
        super().__init__(config)
        self.charset_name = config.extra.get("charset", "alphanum")
        self.min_length = config.extra.get("min_length", 1)
        self.max_length = config.extra.get("max_length", 8)
        self.charset = CHARSETS.get(self.charset_name, self.charset_name)
        
        if not self.charset:
            raise ValueError(f"Unknown charset: {self.charset_name}. Available: {list(CHARSETS.keys())}")
    
    def generate_candidates(self) -> Iterator[str]:
        for length in range(self.min_length, self.max_length + 1):
            for combo in itertools.product(self.charset, repeat=length):
                candidate = ''.join(combo)
                yield candidate
                if self._cancelled:
                    return
    
    def get_info(self) -> dict:
        total = sum(len(self.charset) ** i for i in range(self.min_length, self.max_length + 1))
        return {
            "charset": self.charset_name,
            "charset_size": len(self.charset),
            "min_length": self.min_length,
            "max_length": self.max_length,
            "estimated_total": total,
        }
