"""Unit tests for audit engine."""

import pytest
from jack.core.engine import AuditEngine
from jack.reporting.scoring import PasswordScorer
from jack.reporting.analyzer import PatternAnalyzer


def test_audit_engine_list_attacks():
    engine = AuditEngine()
    attacks = engine.list_attacks()
    assert len(attacks) >= 6


def test_password_scorer():
    scorer = PasswordScorer()
    scores = scorer.score_batch(["password", "AlphaNumeric123!"])
    assert len(scores) == 2
    assert scores[1].score > scores[0].score


def test_pattern_analyzer():
    analyzer = PatternAnalyzer()
    insights = analyzer.analyze(["password", "Password1", "123456"])
    assert isinstance(insights, list)
