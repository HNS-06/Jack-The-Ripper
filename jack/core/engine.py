"""Core audit engine coordinating all subsystems."""

import time
import threading
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field
from ..hashes.detector import HashDetector, DetectionResult
from ..hashes.registry import HashFormatRegistry
from ..hashes.parser import HashParser, ParseOptions
from ..hashes.algorithms.base import HashInfo
from ..attacks.base import AttackConfig, AttackResult, AttackStats
from ..attacks import ATTACK_REGISTRY
from ..attacks.ratelimit import RateLimiter


@dataclass
class EngineConfig:
    """Configuration for the audit engine."""
    hash_file: str = ""
    attack_mode: str = "dictionary"
    wordlist: Optional[str] = None
    mask: Optional[str] = None
    rules: Optional[str] = None
    format_override: Optional[str] = None
    max_candidates: Optional[int] = None
    max_time: Optional[int] = None
    workers: int = 1
    rate_limit: int = 0  # 0 = unlimited
    charset: Optional[str] = None
    min_length: int = 1
    max_length: int = 8
    hash_files: List[str] = field(default_factory=list)
    pipe_source: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class AuditResult:
    """Complete result of an audit run."""
    config: EngineConfig
    detection: Optional[DetectionResult] = None
    attack_stats: Optional[AttackStats] = None
    matches: List[AttackResult] = field(default_factory=list)
    elapsed: float = 0.0
    scored_passwords: list = field(default_factory=list)
    pattern_insights: list = field(default_factory=list)
    duplicate_groups: list = field(default_factory=list)
    rule_suggestions: list = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.matches) > 0

    @property
    def match_count(self) -> int:
        return len(self.matches)


class AuditEngine:
    """Main engine coordinating hash detection, attack execution, and result collection."""

    def __init__(self):
        self.registry = HashFormatRegistry()
        self.detector = HashDetector(self.registry)
        self.parser = HashParser(self.detector)
        self._on_match: Optional[Callable[[AttackResult], None]] = None
        self._on_progress: Optional[Callable[[int, int], None]] = None
        self._current_attack = None
        self._rate_limiter: Optional[RateLimiter] = None

    def set_match_callback(self, callback: Callable[[AttackResult], None]):
        self._on_match = callback

    def set_progress_callback(self, callback: Callable[[int, int], None]):
        self._on_progress = callback

    def detect(self, filepath: str) -> DetectionResult:
        return self.detector.detect_file(filepath)

    def audit(self, config: EngineConfig) -> AuditResult:
        """Execute a full audit."""
        start_time = time.time()

        # Handle piped input
        if config.pipe_source:
            config = self._handle_piped_input(config)

        # Parse hashes
        parse_options = ParseOptions(format_override=config.format_override)

        # Support multi-target
        hash_files = config.hash_files if config.hash_files else [config.hash_file]
        all_hash_infos = []
        for hf in hash_files:
            if hf:
                all_hash_infos.extend(self.parser.parse_file(hf, parse_options))

        if not all_hash_infos:
            raise ValueError("No valid hashes found in input")

        # Detect formats from first file
        detection = None
        if config.hash_file:
            detection = self.detector.detect_file(config.hash_file)

        # Build attack config
        attack_config = AttackConfig(
            mode=config.attack_mode,
            wordlist=config.wordlist,
            mask=config.mask,
            rules=config.rules,
            max_candidates=config.max_candidates,
            max_time=config.max_time,
            format_override=config.format_override,
            extra={
                **config.extra,
                "charset": config.charset,
                "min_length": config.min_length,
                "max_length": config.max_length,
            },
        )

        # Get attack class
        attack_class = ATTACK_REGISTRY.get(config.attack_mode)
        if not attack_class:
            available = ', '.join(ATTACK_REGISTRY.keys())
            raise ValueError(f"Unknown attack mode '{config.attack_mode}'. Available: {available}")

        # Build hash engine lookup
        hash_engines = {}
        for algo in self.registry.get_all_algorithms():
            hash_engines[algo.name.lower()] = algo
            hash_engines[algo.format_id] = algo

        # Create and run attack
        attack = attack_class(attack_config)
        self._current_attack = attack

        # Setup rate limiter
        if config.rate_limit > 0:
            self._rate_limiter = RateLimiter(config.rate_limit)

        matches = []

        def on_match(result: AttackResult):
            matches.append(result)
            if self._on_match:
                self._on_match(result)

        attack.set_match_callback(on_match)

        # Execute attack
        stats = attack.run(all_hash_infos, hash_engines)
        elapsed = time.time() - start_time

        result = AuditResult(
            config=config,
            detection=detection,
            attack_stats=stats,
            matches=matches,
            elapsed=elapsed,
        )

        # Post-audit analysis
        self._run_post_audit_analysis(result)

        return result

    def _run_post_audit_analysis(self, result: AuditResult):
        """Run scoring, pattern analysis, duplicate detection, and rule learning."""
        if not result.matches:
            return

        try:
            from ..reporting.scoring import PasswordScorer
            from ..reporting.analyzer import PatternAnalyzer, DuplicateDetector, RuleLearner

            cracked = [m.candidate for m in result.matches]

            # Score passwords
            scorer = PasswordScorer()
            result.scored_passwords = scorer.score_batch(cracked)

            # Pattern analysis
            analyzer = PatternAnalyzer()
            hash_map = {m.hash_value: m.candidate for m in result.matches}
            result.pattern_insights = analyzer.analyze(cracked, hash_map)

            # Duplicate detection
            detector = DuplicateDetector()
            pairs = [(m.candidate, m.hash_value) for m in result.matches]
            result.duplicate_groups = detector.detect(pairs)

            # Rule learning
            learner = RuleLearner()
            result.rule_suggestions = learner.learn(cracked)
        except Exception:
            pass

    def _handle_piped_input(self, config: EngineConfig) -> EngineConfig:
        """Handle piped stdin input."""
        from ..core.piped import PipedInput
        piped = PipedInput()
        import tempfile
        import os

        words = list(piped.read_hashes(config.pipe_source))
        if words:
            fd, tmp = tempfile.mkstemp(suffix='.txt', prefix='jack_pipe_')
            os.close(fd)
            with open(tmp, 'w', encoding='utf-8') as f:
                for w in words:
                    f.write(w + '\n')
            config.wordlist = tmp
            config.pipe_source = None
        return config

    def cancel(self):
        if self._current_attack:
            self._current_attack.cancel()

    def identify(self, filepath: str) -> str:
        return self.parser.get_detection_summary(filepath)

    def list_formats(self) -> List[dict]:
        return self.registry.list_formats()

    def list_attacks(self) -> List[dict]:
        return [
            {"name": name, "class": cls.__name__, "description": cls.description}
            for name, cls in ATTACK_REGISTRY.items()
        ]
