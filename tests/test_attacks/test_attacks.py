"""Unit tests for attacks module."""

import pytest
from john.attacks.base import AttackConfig
from john.attacks.incremental import IncrementalAttack
from john.attacks.ratelimit import RateLimiter
from john.attacks.ruleparser import RuleFileParser


def test_incremental_attack_generator():
    config = AttackConfig(extra={"charset": "digits", "min_length": 1, "max_length": 3})
    attack = IncrementalAttack(config)
    candidates = list(attack.generate_candidates())
    assert len(candidates) == 10 + 100 + 1000


def test_rate_limiter():
    limiter = RateLimiter(rate=100)
    assert limiter.rate == 100


def test_rule_parser():
    parser = RuleFileParser()
    rules = parser.parse_string("l\nu\nc")
    assert len(rules) == 3
