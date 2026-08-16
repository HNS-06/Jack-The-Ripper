"""Word mutation engine for generating password variants."""

from typing import Iterator, List, Optional, Callable
import itertools
import string


class MutationEngine:
    """Applies mutations to base words to generate password candidates."""
    
    def __init__(self):
        self._mutations: List[Callable[[str], Iterator[str]]] = []
    
    def add_mutation(self, fn: Callable[[str], Iterator[str]]):
        """Add a mutation function."""
        self._mutations.append(fn)
    
    def mutate(self, word: str) -> Iterator[str]:
        """Apply all mutations to a word."""
        yield word  # Original
        for mutation in self._mutations:
            yield from mutation(word)
    
    def mutate_all(self, words: List[str]) -> Iterator[str]:
        """Apply mutations to all words."""
        for word in words:
            yield from self.mutate(word)
    
    @staticmethod
    def capitalize(word: str) -> Iterator[str]:
        """Capitalize first letter."""
        if word:
            yield word[0].upper() + word[1:]
    
    @staticmethod
    def upper(word: str) -> Iterator[str]:
        """Convert to uppercase."""
        yield word.upper()
    
    @staticmethod
    def lower(word: str) -> Iterator[str]:
        """Convert to lowercase."""
        yield word.lower()
    
    @staticmethod
    def append_numbers(word: str, max_digits: int = 4) -> Iterator[str]:
        """Append number suffixes."""
        for length in range(1, max_digits + 1):
            for nums in itertools.product(string.digits, repeat=length):
                yield word + ''.join(nums)
    
    @staticmethod
    def prepend_numbers(word: str, max_digits: int = 4) -> Iterator[str]:
        """Prepend number prefixes."""
        for length in range(1, max_digits + 1):
            for nums in itertools.product(string.digits, repeat=length):
                yield ''.join(nums) + word
    
    @staticmethod
    def append_symbols(word: str, max_symbols: int = 2) -> Iterator[str]:
        """Append symbol suffixes."""
        symbols = string.punctuation
        for length in range(1, max_symbols + 1):
            for syms in itertools.product(symbols, repeat=length):
                yield word + ''.join(syms)
    
    @staticmethod
    def l33t_speak(word: str) -> Iterator[str]:
        """Apply l33t speak substitutions."""
        substitutions = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5'],
            't': ['7'],
            'l': ['1'],
            'b': ['8'],
        }
        
        # Generate single substitutions
        for i, char in enumerate(word.lower()):
            if char in substitutions:
                for sub in substitutions[char]:
                    yield word[:i] + sub + word[i+1:]
    
    @staticmethod
    def reverse(word: str) -> Iterator[str]:
        """Reverse the word."""
        yield word[::-1]
    
    @staticmethod
    def duplicate(word: str, max_times: int = 3) -> Iterator[str]:
        """Duplicate the word."""
        for i in range(2, max_times + 1):
            yield word * i
    
    @staticmethod
    def keyboard_shifts(word: str) -> Iterator[str]:
        """Apply keyboard adjacent character shifts."""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890',
        ]
        
        for i, char in enumerate(word.lower()):
            for row in keyboard_rows:
                if char in row:
                    idx = row.index(char)
                    if idx > 0:
                        yield word[:i] + row[idx - 1] + word[i + 1:]
                    if idx < len(row) - 1:
                        yield word[:i] + row[idx + 1] + word[i + 1:]


class CompositeSource:
    """Combines multiple mutation sources."""
    
    def __init__(self):
        self._sources: List[Callable[[], Iterator[str]]] = []
    
    def add_source(self, source: Callable[[], Iterator[str]]):
        self._sources.append(source)
    
    def generate(self) -> Iterator[str]:
        for source in self._sources:
            yield from source()
