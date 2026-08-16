"""Dictionary attack module."""

from typing import Iterator, Optional
from pathlib import Path
from .base import AttackBase, AttackConfig
from ..candidates.wordlist import WordlistSource


class DictionaryAttack(AttackBase):
    """Dictionary attack using wordlists."""
    
    name = "dictionary"
    description = "Dictionary-based password audit"
    
    def __init__(self, config: AttackConfig):
        super().__init__(config)
        self._wordlist_source: Optional[WordlistSource] = None
    
    def generate_candidates(self) -> Iterator[str]:
        """Generate candidates from wordlist."""
        if not self.config.wordlist:
            raise ValueError("Wordlist path required for dictionary attack")
        
        self._wordlist_source = WordlistSource(
            self.config.wordlist,
            max_words=self.config.max_candidates,
        )
        
        yield from self._wordlist_source.generate()
    
    def get_wordlist_info(self) -> dict:
        """Get information about the wordlist."""
        if not self._wordlist_source:
            return {"status": "not_loaded"}
        
        return {
            "filepath": str(self._wordlist_source.filepath),
            "word_count": self._wordlist_source.count_words(),
        }
