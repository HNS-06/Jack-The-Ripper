"""Rule-based attack module."""

from typing import Iterator, List, Optional, Dict, Any
from dataclasses import dataclass
from .base import AttackBase, AttackConfig
from ..candidates.wordlist import WordlistSource
from ..candidates.mutations import MutationEngine


@dataclass
class RuleOperation:
    """A single rule operation."""
    name: str
    operation: str
    args: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.args is None:
            self.args = {}


class RuleEngine:
    """Applies transformation rules to base words."""
    
    def __init__(self):
        self._rules: List[RuleOperation] = []
        self._presets = self._build_presets()
    
    def _build_presets(self) -> Dict[str, List[RuleOperation]]:
        """Build preset rule collections."""
        return {
            "basic": [
                RuleOperation("lower", "lowercase"),
                RuleOperation("upper", "uppercase"),
                RuleOperation("capitalize", "capitalize"),
                RuleOperation("reverse", "reverse"),
            ],
            "numbers": [
                RuleOperation("append_1digit", "append_numbers", {"max_digits": 1}),
                RuleOperation("append_2digit", "append_numbers", {"max_digits": 2}),
                RuleOperation("prepend_1digit", "prepend_numbers", {"max_digits": 1}),
            ],
            "symbols": [
                RuleOperation("append_symbol", "append_symbols", {"max_symbols": 1}),
                RuleOperation("l33t", "l33t_speak"),
            ],
            "comprehensive": [
                RuleOperation("lower", "lowercase"),
                RuleOperation("upper", "uppercase"),
                RuleOperation("capitalize", "capitalize"),
                RuleOperation("reverse", "reverse"),
                RuleOperation("append_1digit", "append_numbers", {"max_digits": 1}),
                RuleOperation("append_2digit", "append_numbers", {"max_digits": 2}),
                RuleOperation("append_symbol", "append_symbols", {"max_symbols": 1}),
                RuleOperation("l33t", "l33t_speak"),
            ],
        }
    
    def load_preset(self, preset_name: str):
        """Load a preset rule set."""
        if preset_name not in self._presets:
            available = ', '.join(self._presets.keys())
            raise ValueError(f"Unknown preset '{preset_name}'. Available: {available}")
        self._rules = self._presets[preset_name][:]
    
    def add_rule(self, rule: RuleOperation):
        """Add a custom rule."""
        self._rules.append(rule)
    
    def apply(self, word: str) -> Iterator[str]:
        """Apply all rules to a word."""
        engine = MutationEngine()
        
        yield word  # Always yield original
        
        for rule in self._rules:
            mutation_fn = getattr(engine, rule.operation, None)
            if mutation_fn:
                if rule.args:
                    yield from mutation_fn(word, **rule.args)
                else:
                    yield from mutation_fn(word)
    
    def list_presets(self) -> List[str]:
        """List available presets."""
        return list(self._presets.keys())


class RuleAttack(AttackBase):
    """Rule-based dictionary attack."""
    
    name = "rules"
    description = "Rule-based dictionary audit"
    
    def __init__(self, config: AttackConfig):
        super().__init__(config)
        self.rule_engine = RuleEngine()
        
        # Load rules
        if config.rules:
            if config.rules in self.rule_engine.list_presets():
                self.rule_engine.load_preset(config.rules)
            else:
                # Treat as comma-separated operations
                for op_name in config.rules.split(','):
                    op_name = op_name.strip()
                    if hasattr(MutationEngine, op_name):
                        self.rule_engine.add_rule(
                            RuleOperation(op_name, op_name)
                        )
    
    def generate_candidates(self) -> Iterator[str]:
        """Generate candidates by applying rules to wordlist."""
        if not self.config.wordlist:
            raise ValueError("Wordlist required for rule attack")
        
        wordlist = WordlistSource(self.config.wordlist)
        
        for word in wordlist.generate():
            yield from self.rule_engine.apply(word)
