"""Password strength scoring and audit analytics."""

import re
import math
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class PasswordScore:
    """Strength score for a single password."""
    password: str
    score: int  # 0-100
    strength: str  # very_weak, weak, moderate, strong, very_strong
    entropy: float
    patterns_found: List[str] = field(default_factory=list)
    category: str = "unknown"
    
    def to_dict(self) -> dict:
        return {
            "password": self.password,
            "score": self.score,
            "strength": self.strength,
            "entropy": round(self.entropy, 2),
            "patterns": self.patterns_found,
            "category": self.category,
        }


@dataclass
class AuditScoring:
    """Aggregate scoring for an audit run."""
    total_hashes: int = 0
    recovered: int = 0
    unrecovered: int = 0
    scores: List[PasswordScore] = field(default_factory=list)
    
    @property
    def recovery_rate(self) -> float:
        if self.total_hashes > 0:
            return self.recovered / self.total_hashes * 100
        return 0.0
    
    @property
    def avg_score(self) -> float:
        if self.scores:
            return sum(s.score for s in self.scores) / len(self.scores)
        return 0.0
    
    @property
    def strength_distribution(self) -> Dict[str, int]:
        dist = Counter(s.strength for s in self.scores)
        return dict(dist)
    
    @property
    def category_distribution(self) -> Dict[str, int]:
        return dict(Counter(s.category for s in self.scores))


class PasswordScorer:
    """Score passwords using zxcvbn-inspired analysis."""
    
    # Common passwords list (top 100)
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
        "qazwsx", "michael", "football", "password1", "password123", "admin",
        "welcome", "hello", "charlie", "donald", "login", "princess", "starwars",
        "solo", "passw0rd", "123456789", "1234567890", "000000", "access",
    }
    
    KEYBOARD_PATTERNS = [
        "qwerty", "asdfgh", "zxcvbn", "qazwsx", "123456", "abcdef",
        "qwertyuiop", "asdfghjkl",
    ]
    
    def score_password(self, password: str) -> PasswordScore:
        """Score a single password (0-100)."""
        if not password:
            return PasswordScore("", 0, "very_weak", 0.0)
        
        score = 0
        entropy = self._calculate_entropy(password)
        patterns = []
        category = "custom"
        
        # Length scoring
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 5
        else:
            score -= 10
            patterns.append("short")
        
        # Character diversity
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32
        
        diversity = sum([has_lower, has_upper, has_digit, has_symbol])
        score += diversity * 10
        
        # Pattern detection
        lower_pw = password.lower()
        
        if lower_pw in self.COMMON_PASSWORDS:
            score -= 50
            patterns.append("common_password")
            category = "common"
        
        for pat in self.KEYBOARD_PATTERNS:
            if pat in lower_pw:
                score -= 30
                patterns.append("keyboard_pattern")
                category = "keyboard"
                break
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 15
            patterns.append("repeated_chars")
        
        # Sequential characters
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', lower_pw):
            score -= 15
            patterns.append("sequential_letters")
            category = "sequential"
        
        if re.search(r'(012|123|234|345|456|567|678|789)', lower_pw):
            score -= 15
            patterns.append("sequential_digits")
            category = "sequential"
        
        # Date patterns
        if re.search(r'(19|20)\d{2}', password):
            score -= 10
            patterns.append("contains_year")
            category = "date"
        
        if re.search(r'\d{2}[-/]\d{2}[-/]\d{2,4}', password):
            score -= 15
            patterns.append("date_pattern")
            category = "date"
        
        # Numeric-only
        if password.isdigit():
            score -= 20
            patterns.append("numeric_only")
            category = "numeric"
        
        # Letter-only
        if password.isalpha():
            score -= 5
            patterns.append("letters_only")
        
        # L33t speak detection
        l33t_chars = set(password) & set("@3!10$5")
        if l33t_chars and len(l33t_chars) >= 2:
            score += 5
            patterns.append("l33t_speak")
        
        # Entropy bonus
        if entropy > 60:
            score += 10
        elif entropy > 40:
            score += 5
        
        # Clamp score
        score = max(0, min(100, score))
        
        # Determine strength label
        if score >= 80:
            strength = "very_strong"
        elif score >= 60:
            strength = "strong"
        elif score >= 40:
            strength = "moderate"
        elif score >= 20:
            strength = "weak"
        else:
            strength = "very_weak"
        
        return PasswordScore(
            password=password,
            score=score,
            strength=strength,
            entropy=entropy,
            patterns_found=patterns,
            category=category,
        )
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of a password."""
        if not password:
            return 0.0
        
        freq = Counter(password)
        length = len(password)
        entropy = 0.0
        
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        # Scale by length
        return entropy * length / len(password) if password else 0.0
    
    def score_batch(self, passwords: List[str]) -> List[PasswordScore]:
        return [self.score_password(pw) for pw in passwords]
    
    def audit_summary(self, total_hashes: int, recovered_passwords: List[str]) -> AuditScoring:
        scores = self.score_batch(recovered_passwords)
        return AuditScoring(
            total_hashes=total_hashes,
            recovered=len(recovered_passwords),
            unrecovered=total_hashes - len(recovered_passwords),
            scores=scores,
        )