"""Bloom filter for probabilistic deduplication of large candidate streams."""

import math
import struct
from typing import Optional


class BloomFilter:
    """Space-efficient probabilistic set for deduplication.

    For 1M items with 1% FPR: ~1.2MB memory vs ~40MB for a set.
    """

    def __init__(self, expected_items: int = 1_000_000, fp_rate: float = 0.01):
        self.expected_items = expected_items
        self.fp_rate = fp_rate
        self.size = self._optimal_size(expected_items, fp_rate)
        self.num_hashes = self._optimal_hash_count(self.size, expected_items)
        self._bits = bytearray((self.size + 7) // 8)
        self._count = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        k = (m / n) * math.log(2)
        return max(1, int(k))

    def _hashes(self, item: str) -> list:
        data = item.encode('utf-8')
        h1 = self._fnv1a(data)
        h2 = self._murmur3(data)
        return [(h1 + i * h2) % self.size for i in range(self.num_hashes)]

    @staticmethod
    def _fnv1a(data: bytes) -> int:
        h = 0x811c9dc5
        for byte in data:
            h ^= byte
            h = (h * 0x01000193) & 0xFFFFFFFF
        return h

    @staticmethod
    def _murmur3(data: bytes) -> int:
        h = 0xdeadbeef
        for i in range(0, len(data), 4):
            k = struct.unpack('<I', data[i:i+4].ljust(4, b'\x00'))[0]
            k = (k * 0xcc9e2d51) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * 0x1b873593) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
        h ^= len(data)
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= h >> 16
        return h

    def add(self, item: str) -> bool:
        """Add item. Returns True if likely already present (false positive)."""
        positions = self._hashes(item)
        already_present = True
        for pos in positions:
            byte_idx, bit_idx = pos // 8, pos % 8
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                already_present = False
                self._bits[byte_idx] |= (1 << bit_idx)
        if not already_present:
            self._count += 1
        return already_present

    def contains(self, item: str) -> bool:
        for pos in self._hashes(item):
            byte_idx, bit_idx = pos // 8, pos % 8
            if not (self._bits[byte_idx] & (1 << bit_idx)):
                return False
        return True

    @property
    def count(self) -> int:
        return self._count

    @property
    def memory_bytes(self) -> int:
        return len(self._bits)

    @property
    def memory_human(self) -> str:
        size = self.memory_bytes
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def __contains__(self, item: str) -> bool:
        return self.contains(item)

    def __len__(self) -> int:
        return self._count

    def __repr__(self) -> str:
        return f"BloomFilter(items={self.expected_items}, fpr={self.fp_rate}, bits={self.size}, hashes={self.num_hashes}, mem={self.memory_human})"
