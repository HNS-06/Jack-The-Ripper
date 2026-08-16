"""Unit tests for candidate generators."""

import pytest
from jack.candidates.charset import CharsetGenerator


def test_charset_generator_digits():
    cg = CharsetGenerator.from_name("digits", 1, 4)
    assert cg.estimate_count() == 10 + 100 + 1000 + 10000


def test_charset_generator_custom():
    cg = CharsetGenerator(charset="abc", min_length=1, max_length=2)
    assert cg.estimate_count() == 3 + 9
