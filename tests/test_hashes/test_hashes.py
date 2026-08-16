"""Unit tests for hash detection and registry."""

import pytest
from john.hashes.detector import HashDetector
from john.hashes.registry import HashFormatRegistry
from john.hashes.rainbow import RainbowTableDetector


def test_hash_detector_md5():
    detector = HashDetector()
    result = detector.detect_lines(["5f4dcc3b5aa765d61d8327deb882cf99"])
    assert result.valid_hashes == 1
    assert result.primary_format == "md5"


def test_hash_detector_sha256():
    detector = HashDetector()
    result = detector.detect_lines(["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"])
    assert result.valid_hashes == 1
    assert result.primary_format == "sha256"


def test_rainbow_table_detector():
    rtd = RainbowTableDetector()
    hashes = ["5f4dcc3b5aa765d61d8327deb882cf99", "014dcc3b5aa765d61d8327deb882cf99"]
    results = rtd.analyze_batch(hashes)
    assert isinstance(results, list)
    dist = rtd.analyze_format_distribution(hashes)
    assert dist["total_hashes"] == 2
