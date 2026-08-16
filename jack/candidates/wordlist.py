"""Wordlist-based candidate source."""

from typing import Iterator, Optional
from pathlib import Path


class WordlistSource:
    """Generates candidates from a wordlist file."""
    
    def __init__(
        self,
        filepath: str,
        encoding: str = 'utf-8',
        skip_comments: bool = True,
        comment_char: str = '#',
        strip_whitespace: bool = True,
        max_words: Optional[int] = None,
    ):
        self.filepath = Path(filepath)
        self.encoding = encoding
        self.skip_comments = skip_comments
        self.comment_char = comment_char
        self.strip_whitespace = strip_whitespace
        self.max_words = max_words
    
    def generate(self) -> Iterator[str]:
        """Stream words from the wordlist file."""
        if not self.filepath.exists():
            raise FileNotFoundError(f"Wordlist not found: {self.filepath}")
        
        count = 0
        with open(self.filepath, 'r', encoding=self.encoding, errors='ignore') as f:
            for line in f:
                if self.max_words and count >= self.max_words:
                    return
                
                word = line.rstrip('\n\r')
                if self.strip_whitespace:
                    word = word.strip()
                
                if not word:
                    continue
                
                if self.skip_comments and word.startswith(self.comment_char):
                    continue
                
                count += 1
                yield word
    
    def count_words(self) -> int:
        """Count total words in the wordlist without loading them."""
        if not self.filepath.exists():
            return 0
        
        count = 0
        with open(self.filepath, 'r', encoding=self.encoding, errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not (self.skip_comments and word.startswith(self.comment_char)):
                    count += 1
        return count
    
    def __repr__(self) -> str:
        return f"WordlistSource({self.filepath})"
