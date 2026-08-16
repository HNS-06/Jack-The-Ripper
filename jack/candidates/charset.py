"""Custom charset generator for targeted brute force."""

from typing import Iterator, List
import itertools


class CharsetGenerator:
    """Generate candidates from a custom character set with length range."""
    
    def __init__(self, charset: str, min_length: int = 1, max_length: int = 8):
        self.charset = charset
        self.min_length = min_length
        self.max_length = max_length
    
    def generate(self) -> Iterator[str]:
        for length in range(self.min_length, self.max_length + 1):
            for combo in itertools.product(self.charset, repeat=length):
                yield ''.join(combo)
    
    def estimate_count(self) -> int:
        cs = len(self.charset)
        return sum(cs ** i for i in range(self.min_length, self.max_length + 1))
    
    @staticmethod
    def from_name(name: str, min_length: int = 1, max_length: int = 8) -> 'CharsetGenerator':
        charsets = {
            "digits": "0123456789",
            "lower": "abcdefghijklmnopqrstuvwxyz",
            "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "alphanum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "hex": "0123456789abcdef",
            "hex-upper": "0123456789ABCDEF",
            "symbols": "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
            "braces": "{}[]()",
            "html": "<>&\"'",
            "sql": "'\";--",
        }
        charset = charsets.get(name, name)
        return CharsetGenerator(charset, min_length, max_length)
    
    def __repr__(self) -> str:
        return f"CharsetGenerator(len={len(self.charset)}, range={self.min_length}-{self.max_length})"
