"""Attack engine modules."""

from .base import AttackBase, AttackConfig, AttackResult, AttackStats
from .dictionary import DictionaryAttack
from .mask import MaskAttack
from .rules import RuleAttack
from .hybrid import HybridAttack
from .patterns import PatternAttack
from .incremental import IncrementalAttack

ATTACK_REGISTRY = {
    "dictionary": DictionaryAttack,
    "mask": MaskAttack,
    "rules": RuleAttack,
    "hybrid": HybridAttack,
    "pattern": PatternAttack,
    "incremental": IncrementalAttack,
}

__all__ = [
    "AttackBase", "AttackConfig", "AttackResult", "AttackStats",
    "DictionaryAttack", "MaskAttack", "RuleAttack", "HybridAttack",
    "PatternAttack", "IncrementalAttack", "ATTACK_REGISTRY",
]
