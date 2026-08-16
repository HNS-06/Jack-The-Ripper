"""Hybrid attack combining dictionary with mutations."""

from typing import Iterator
from .base import AttackBase, AttackConfig
from ..candidates.wordlist import WordlistSource
from ..candidates.mutations import MutationEngine


class HybridAttack(AttackBase):
    """Hybrid attack: dictionary + numeric suffix + symbol mutation."""
    
    name = "hybrid"
    description = "Hybrid dictionary + mutation audit"
    
    def __init__(self, config: AttackConfig):
        super().__init__(config)
        self._stages = config.extra.get('stages', ['numbers', 'symbols'])
    
    def generate_candidates(self) -> Iterator[str]:
        """Generate candidates through hybrid approach."""
        if not self.config.wordlist:
            raise ValueError("Wordlist required for hybrid attack")
        
        wordlist = WordlistSource(self.config.wordlist)
        engine = MutationEngine()
        
        for word in wordlist.generate():
            # Stage 1: Base word
            yield word
            
            # Stage 2: Capitalization variants
            yield from engine.capitalize(word)
            yield from engine.upper(word)
            
            # Stage 3: Number suffixes
            if 'numbers' in self._stages:
                yield from engine.append_numbers(word, max_digits=2)
            
            # Stage 4: Symbol suffixes
            if 'symbols' in self._stages:
                yield from engine.append_symbols(word, max_symbols=1)
            
            # Stage 5: L33t speak
            if 'l33t' in self._stages:
                yield from engine.l33t_speak(word)
            
            # Stage 6: Combined mutations
            if 'combined' in self._stages:
                for num_suffix in ['1', '12', '!', '1!', '!1']:
                    yield word + num_suffix
                    capitalized = word[0].upper() + word[1:] if word else word
                    yield capitalized + num_suffix
