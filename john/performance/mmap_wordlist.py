"""Memory-mapped wordlist for handling multi-GB files without RAM pressure."""

import mmap
from pathlib import Path
from typing import Iterator, Optional


class MmapWordlist:
    """Memory-mapped wordlist for efficient large file access."""

    def __init__(self, filepath: str, encoding: str = 'utf-8'):
        self.filepath = Path(filepath)
        self.encoding = encoding
        self._file = None
        self._mmap = None
        self._size = 0
        self._line_offsets: list = []
        self._indexed = False

    def open(self):
        if not self.filepath.exists():
            raise FileNotFoundError(f"Wordlist not found: {self.filepath}")
        self._file = open(self.filepath, 'rb')
        self._size = self.filepath.stat().st_size
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self):
        if self._mmap:
            self._mmap.close()
            self._mmap = None
        if self._file:
            self._file.close()
            self._file = None

    def build_index(self):
        if self._indexed:
            return
        self._line_offsets = [0]
        pos = 0
        while pos < self._size:
            newline_pos = self._mmap.find(b'\n', pos)
            if newline_pos == -1:
                break
            pos = newline_pos + 1
            if pos < self._size:
                self._line_offsets.append(pos)
        self._indexed = True

    def __iter__(self) -> Iterator[str]:
        if self._mmap is None:
            self.open()
        pos = 0
        while pos < self._size:
            newline_pos = self._mmap.find(b'\n', pos)
            line = self._mmap[pos:newline_pos] if newline_pos != -1 else self._mmap[pos:]
            word = line.decode(self.encoding, errors='ignore').rstrip('\r\n')
            if word and not word.startswith('#'):
                yield word
            if newline_pos == -1:
                break
            pos = newline_pos + 1

    def get_line(self, index: int) -> Optional[str]:
        if not self._indexed:
            self.build_index()
        if index >= len(self._line_offsets):
            return None
        start = self._line_offsets[index]
        end = self._line_offsets[index + 1] if index + 1 < len(self._line_offsets) else self._size
        return self._mmap[start:end].decode(self.encoding, errors='ignore').rstrip('\r\n')

    def count_lines(self) -> int:
        if self._mmap is None:
            self.open()
        count = 0
        pos = 0
        while pos < self._size:
            newline_pos = self._mmap.find(b'\n', pos)
            if newline_pos == -1:
                break
            pos = newline_pos + 1
            count += 1
        return count

    @property
    def size_bytes(self) -> int:
        return self._size

    @property
    def size_human(self) -> str:
        size = self._size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        return f"MmapWordlist({self.filepath.name}, {self.size_human})"
