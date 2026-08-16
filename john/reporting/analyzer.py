"""Post-audit pattern analysis and insights."""

import re
from typing import List, Dict, Tuple
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class PatternInsight:
    """A detected pattern in recovered passwords."""
    pattern_type: str
    description: str
    count: int
    examples: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    
    def to_dict(self) -> dict:
        return {
            "type": self.pattern_type,
            "description": self.description,
            "count": self.count,
            "examples": self.examples[:5],
            "risk": self.risk_level,
        }


@dataclass
class DuplicateGroup:
    """Group of hashes sharing the same password."""
    password: str
    count: int
    hash_values: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "password": self.password[:20] + "..." if len(self.password) > 20 else self.password,
            "reuse_count": self.count,
            "affected_hashes": len(self.hash_values),
        }


class PatternAnalyzer:
    """Analyze patterns in recovered passwords for security insights."""
    
    def __init__(self):
        self._insights: List[PatternInsight] = []
    
    def analyze(self, passwords: List[str], hash_mapping: Dict[str, str] = None) -> List[PatternInsight]:
        """Run all pattern analysis on recovered passwords."""
        self._insights.clear()
        
        if not passwords:
            return self._insights
        
        self._detect_common_prefixes(passwords)
        self._detect_common_suffixes(passwords)
        self._detect_length_distribution(passwords)
        self._detect_character_patterns(passwords)
        self._detect_reuse(passwords, hash_mapping or {})
        self._detect_keyboard_walks(passwords)
        self._detect_dates(passwords)
        self._detect_names(passwords)
        
        return self._insights
    
    def _detect_common_prefixes(self, passwords: List[str]):
        prefixes = Counter()
        for pw in passwords:
            if len(pw) >= 3:
                prefixes[pw[:3]] += 1
        
        common = [(p, c) for p, c in prefixes.most_common(5) if c >= 3]
        if common:
            examples = [p for p, _ in common]
            self._insights.append(PatternInsight(
                pattern_type="common_prefix",
                description=f"Multiple passwords share common 3-char prefixes",
                count=sum(c for _, c in common),
                examples=examples,
                risk_level="medium",
            ))
    
    def _detect_common_suffixes(self, passwords: List[str]):
        suffixes = Counter()
        for pw in passwords:
            if len(pw) >= 3:
                suffixes[pw[-3:]] += 1
        
        common = [(s, c) for s, c in suffixes.most_common(5) if c >= 3]
        if common:
            examples = [s for s, _ in common]
            self._insights.append(PatternInsight(
                pattern_type="common_suffix",
                description=f"Multiple passwords share common 3-char suffixes",
                count=sum(c for _, c in common),
                examples=examples,
                risk_level="medium",
            ))
    
    def _detect_length_distribution(self, passwords: List[str]):
        lengths = Counter(len(pw) for pw in passwords)
        short = sum(c for l, c in lengths.items() if l < 8)
        if short > 0:
            pct = short / len(passwords) * 100
            self._insights.append(PatternInsight(
                pattern_type="short_passwords",
                description=f"{short} passwords ({pct:.0f}%) are shorter than 8 characters",
                count=short,
                risk_level="high" if pct > 50 else "medium",
            ))
    
    def _detect_character_patterns(self, passwords: List[str]):
        numeric_only = sum(1 for pw in passwords if pw.isdigit())
        alpha_only = sum(1 for pw in passwords if pw.isalpha() and not pw.isnumeric())
        
        if numeric_only > 0:
            self._insights.append(PatternInsight(
                pattern_type="numeric_only",
                description=f"{numeric_only} passwords are numeric-only",
                count=numeric_only,
                examples=[pw for pw in passwords if pw.isdigit()][:3],
                risk_level="high",
            ))
    
    def _detect_reuse(self, passwords: List[str], hash_mapping: Dict[str, str]):
        pw_counts = Counter(passwords)
        reused = [(pw, c) for pw, c in pw_counts.most_common() if c > 1]
        
        for pw, count in reused[:10]:
            self._insights.append(PatternInsight(
                pattern_type="password_reuse",
                description=f"Password reused across {count} accounts",
                count=count,
                examples=[pw],
                risk_level="critical" if count >= 5 else "high",
            ))
    
    def _detect_keyboard_walks(self, passwords: List[str]):
        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
        walks = []
        
        for pw in passwords:
            lower = pw.lower()
            for row in keyboard_rows:
                for i in range(len(lower) - 2):
                    substring = lower[i:i+3]
                    if substring in row or substring[::-1] in row:
                        walks.append(pw)
                        break
        
        if walks:
            self._insights.append(PatternInsight(
                pattern_type="keyboard_walk",
                description=f"{len(walks)} passwords contain keyboard walk patterns",
                count=len(walks),
                examples=walks[:5],
                risk_level="high",
            ))
    
    def _detect_dates(self, passwords: List[str]):
        date_patterns = []
        for pw in passwords:
            if re.search(r'(19|20)\d{2}', pw):
                date_patterns.append(pw)
            elif re.search(r'\d{2}[/-]\d{2}[/-]\d{2,4}', pw):
                date_patterns.append(pw)
        
        if date_patterns:
            self._insights.append(PatternInsight(
                pattern_type="date_pattern",
                description=f"{len(date_patterns)} passwords contain date patterns",
                count=len(date_patterns),
                examples=date_patterns[:5],
                risk_level="medium",
            ))
    
    def _detect_names(self, passwords: List[str]):
        common_names = {
            "john", "james", "robert", "michael", "david", "william", "richard",
            "joseph", "thomas", "christopher", "mary", "patricia", "jennifer",
            "linda", "barbara", "elizabeth", "susan", "jessica", "sarah",
        }
        
        name_passwords = []
        for pw in passwords:
            lower = pw.lower()
            for name in common_names:
                if name in lower:
                    name_passwords.append(pw)
                    break
        
        if name_passwords:
            self._insights.append(PatternInsight(
                pattern_type="contains_name",
                description=f"{len(name_passwords)} passwords contain common names",
                count=len(name_passwords),
                examples=name_passwords[:5],
                risk_level="high",
            ))
    
    def get_summary(self) -> Dict:
        return {
            "total_insights": len(self._insights),
            "critical": sum(1 for i in self._insights if i.risk_level == "critical"),
            "high": sum(1 for i in self._insights if i.risk_level == "high"),
            "medium": sum(1 for i in self._insights if i.risk_level == "medium"),
            "insights": [i.to_dict() for i in self._insights],
        }


class DuplicateDetector:
    """Detect duplicate passwords across hash sets."""
    
    def __init__(self):
        self._groups: List[DuplicateGroup] = []
    
    def detect(self, password_hash_pairs: List[Tuple[str, str]]) -> List[DuplicateGroup]:
        """Find groups of hashes with the same password.
        
        Args:
            password_hash_pairs: List of (password, hash_value) tuples
        """
        from collections import defaultdict
        groups = defaultdict(list)
        
        for pw, h in password_hash_pairs:
            groups[pw].append(h)
        
        self._groups = []
        for pw, hashes in groups.items():
            if len(hashes) > 1:
                self._groups.append(DuplicateGroup(
                    password=pw,
                    count=len(hashes),
                    hash_values=hashes,
                ))
        
        self._groups.sort(key=lambda g: g.count, reverse=True)
        return self._groups
    
    def get_summary(self) -> Dict:
        total_affected = sum(g.count for g in self._groups)
        return {
            "duplicate_groups": len(self._groups),
            "total_affected_hashes": total_affected,
            "groups": [g.to_dict() for g in self._groups[:20]],
        }


class RuleLearner:
    """Analyze cracked passwords to generate effective rules for unrecovered hashes."""
    
    def __init__(self):
        self._suggested_rules: List[Dict] = []
    
    def learn(self, cracked_passwords: List[str]) -> List[Dict]:
        """Analyze cracked passwords and suggest rules."""
        self._suggested_rules.clear()
        
        if not cracked_passwords:
            return self._suggested_rules
        
        # Detect capitalization patterns
        cap_first = sum(1 for pw in cracked_passwords if pw and pw[0].isupper())
        if cap_first > len(cracked_passwords) * 0.1:
            self._suggested_rules.append({
                "rule": "capitalize",
                "reason": f"{cap_first}/{len(cracked_passwords)} passwords are capitalized",
                "priority": "high",
            })
        
        # Detect number suffixes
        num_suffix = sum(1 for pw in cracked_passwords if pw and pw[-1].isdigit())
        if num_suffix > len(cracked_passwords) * 0.1:
            self._suggested_rules.append({
                "rule": "append_numbers",
                "reason": f"{num_suffix}/{len(cracked_passwords)} passwords end with digits",
                "priority": "high",
            })
        
        # Detect symbol suffixes
        sym_suffix = sum(1 for pw in cracked_passwords if pw and not pw[-1].isalnum())
        if sym_suffix > len(cracked_passwords) * 0.05:
            self._suggested_rules.append({
                "rule": "append_symbols",
                "reason": f"{sym_suffix}/{len(cracked_passwords)} passwords end with symbols",
                "priority": "medium",
            })
        
        # Detect l33t speak
        l33t = sum(1 for pw in cracked_passwords if any(c in pw for c in '@3!10$5'))
        if l33t > len(cracked_passwords) * 0.05:
            self._suggested_rules.append({
                "rule": "l33t",
                "reason": f"{l33t}/{len(cracked_passwords)} passwords use l33t substitutions",
                "priority": "medium",
            })
        
        # Detect common suffixes
        suffixes = Counter()
        for pw in cracked_passwords:
            if len(pw) >= 2:
                suffixes[pw[-2:]] += 1
        
        for suffix, count in suffixes.most_common(5):
            if count >= 3:
                self._suggested_rules.append({
                    "rule": f"append_{suffix}",
                    "reason": f"Common suffix '{suffix}' found in {count} passwords",
                    "priority": "medium",
                })
        
        # Detect common prefixes
        prefixes = Counter()
        for pw in cracked_passwords:
            if len(pw) >= 2:
                prefixes[pw[:2]] += 1
        
        for prefix, count in prefixes.most_common(5):
            if count >= 3:
                self._suggested_rules.append({
                    "rule": f"prepend_{prefix}",
                    "reason": f"Common prefix '{prefix}' found in {count} passwords",
                    "priority": "medium",
                })
        
        # Average length
        avg_len = sum(len(pw) for pw in cracked_passwords) / len(cracked_passwords)
        self._suggested_rules.append({
            "rule": f"target_length_{int(avg_len)}",
            "reason": f"Average cracked password length is {avg_len:.1f} characters",
            "priority": "info",
        })
        
        return self._suggested_rules
    
    def get_summary(self) -> Dict:
        return {
            "total_suggestions": len(self._suggested_rules),
            "high_priority": sum(1 for r in self._suggested_rules if r["priority"] == "high"),
            "suggestions": self._suggested_rules,
        }