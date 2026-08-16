"""Mask-based candidate generation."""

from typing import Iterator, Optional, List
from itertools import product
import string


MASK_CHARS = {
    '?l': string.ascii_lowercase,
    '?u': string.ascii_uppercase,
    '?d': string.digits,
    '?s': string.punctuation,
    '?a': string.ascii_letters + string.digits + string.punctuation,
    '?b': ''.join(chr(i) for i in range(256)),
}

MASK_LENGTHS = {
    '?l': 1,
    '?u': 1,
    '?d': 1,
    '?s': 1,
    '?a': 1,
    '?b': 1,
}


class MaskSource:
    """Generate candidates from a mask pattern.
    
    Mask examples:
        '????'       - 4 lowercase letters
        '?u?l?l?l'   - Capital followed by 3 lowercase
        '?d?d?d?d'   - 4 digits
        '?a?a?a?a?a' - 5 mixed characters
    """
    
    def __init__(self, mask: str, max_length: Optional[int] = None):
        self.mask = mask
        self.max_length = max_length or 64
        self._segments = self._parse_mask(mask)
    
    def _parse_mask(self, mask: str) -> List[List[str]]:
        """Parse mask into character segments."""
        segments = []
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                key = mask[i:i+2]
                if key in MASK_CHARS:
                    segments.append(MASK_CHARS[key])
                    i += 2
                    continue
            # Literal character
            segments.append([mask[i]])
            i += 1
        return segments
    
    def generate(self) -> Iterator[str]:
        """Generate all candidates matching the mask."""
        if not self._segments:
            return
        
        # Check total length
        total_length = len(self._segments)
        if total_length > self.max_length:
            return
        
        for combo in product(*self._segments):
            yield ''.join(combo)
    
    def estimate_count(self) -> int:
        """Estimate total number of candidates."""
        count = 1
        for segment in self._segments:
            count *= len(segment)
            if count > 10**12:  # Cap at 1 trillion
                return -1  # Too large to enumerate
        return count
    
    def __repr__(self) -> str:
        return f"MaskSource({self.mask})"
