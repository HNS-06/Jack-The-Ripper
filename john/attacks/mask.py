"""Mask attack module."""

from typing import Iterator
from .base import AttackBase, AttackConfig
from ..candidates.masks import MaskSource


class MaskAttack(AttackBase):
    """Mask-based brute force attack."""
    
    name = "mask"
    description = "Mask-based brute force audit"
    
    def __init__(self, config: AttackConfig):
        super().__init__(config)
        self._mask_source: Optional[MaskSource] = None
    
    def generate_candidates(self) -> Iterator[str]:
        """Generate candidates from mask pattern."""
        if not self.config.mask:
            raise ValueError("Mask pattern required for mask attack")
        
        self._mask_source = MaskSource(
            self.config.mask,
            max_length=self.config.extra.get('max_length', 64),
        )
        
        yield from self._mask_source.generate()
    
    def get_mask_info(self) -> dict:
        """Get information about the mask."""
        if not self._mask_source:
            return {"status": "not_loaded"}
        
        return {
            "mask": self._mask_source.mask,
            "estimated_count": self._mask_source.estimate_count(),
        }
