"""Rainbow table detection for pre-computed hash identification."""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class RainbowIndicator:
    """Indicator that a hash may be from a rainbow table."""
    hash_value: str
    confidence: float  # 0-1
    indicators: List[str] = field(default_factory=list)
    likely_source: str = "unknown"
    
    def to_dict(self) -> dict:
        return {
            "hash": self.hash_value[:30] + "..." if len(self.hash_value) > 30 else self.hash_value,
            "confidence": round(self.confidence, 2),
            "indicators": self.indicators,
            "source": self.likely_source,
        }


class RainbowTableDetector:
    """Detect hashes that may come from pre-computed rainbow tables."""
    
    # Known rainbow table patterns (hash prefix patterns)
    KNOWN_PATTERNS = {
        # MD5彩虹表常用前缀
        "md5_generic": {"prefix": "", "length": 32, "pattern": r'^[a-f0-9]{32}$'},
        "lm_ntlm": {"prefix": "", "length": 32, "pattern": r'^[a-fA-F0-9]{32}$'},
        # Common hashcat output formats
        "hashcat_md5": {"prefix": "", "length": 32, "pattern": r'^[a-f0-9]{32}$'},
    }
    
    # Characteristic patterns of rainbow table hashes
    def __init__(self):
        self._indicators: List[RainbowIndicator] = []
    
    def analyze_batch(self, hashes: List[str]) -> List[RainbowIndicator]:
        """Analyze a batch of hashes for rainbow table indicators."""
        self._indicators.clear()
        
        if not hashes:
            return self._indicators
        
        # Check for uniform hash lengths (rainbow tables target specific formats)
        length_counts = Counter(len(h) for h in hashes)
        
        # Check for statistical anomalies
        for hash_str in hashes:
            indicators = []
            confidence = 0.0
            
            # Check hex uniformity
            if re.match(r'^[a-f0-9]+$', hash_str):
                freq = Counter(hash_str)
                expected_freq = len(hash_str) / 16
                
                # Low chi-square = too uniform (suspicious)
                chi_sq = sum((freq.get(c, 0) - expected_freq) ** 2 / expected_freq
                            for c in '0123456789abcdef')
                
                if chi_sq < 5:  # Very uniform
                    indicators.append("unusual_hex_distribution")
                    confidence += 0.3
            
            # Check for short hash in known format
            if len(hash_str) == 32:
                indicators.append("md5_length")
                confidence += 0.1
            
            # Check for common hash prefixes
            if hash_str.startswith('01') or hash_str.startswith('ff'):
                indicators.append("common_prefix")
                confidence += 0.1
            
            # Check if hash looks like it could be from a dictionary attack
            # (all lowercase hex, no unusual chars)
            if re.match(r'^[a-f0-9]{32}$', hash_str):
                indicators.append("standard_md5_format")
                confidence += 0.1
            
            if indicators and confidence > 0.2:
                source = self._guess_source(hash_str, indicators)
                self._indicators.append(RainbowIndicator(
                    hash_value=hash_str,
                    confidence=min(confidence, 1.0),
                    indicators=indicators,
                    likely_source=source,
                ))
        
        return self._indicators
    
    def _guess_source(self, hash_str: str, indicators: List[str]) -> str:
        """Guess the likely source of a rainbow table hash."""
        if "md5_length" in indicators:
            return "md5_rainbow_table"
        return "unknown"
    
    def analyze_format_distribution(self, hashes: List[str]) -> Dict:
        """Analyze format distribution for suspicious uniformity."""
        length_counts = Counter(len(h) for h in hashes)
        
        suspicious = []
        for length, count in length_counts.items():
            if count > len(hashes) * 0.9:
                suspicious.append({
                    "length": length,
                    "count": count,
                    "percentage": count / len(hashes) * 100,
                    "note": "Overwhelming majority - possible rainbow table input",
                })
        
        return {
            "total_hashes": len(hashes),
            "unique_lengths": len(length_counts),
            "distribution": dict(length_counts.most_common(10)),
            "suspicious": suspicious,
        }
    
    def get_summary(self) -> Dict:
        return {
            "total_flagged": len(self._indicators),
            "high_confidence": sum(1 for i in self._indicators if i.confidence > 0.5),
            "indicators": [i.to_dict() for i in self._indicators[:50]],
        }
