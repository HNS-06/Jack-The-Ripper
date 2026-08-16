"""Parser for John the Ripper native .rule file syntax."""

import re
from typing import List, Iterator, Optional
from dataclasses import dataclass
from ..candidates.mutations import MutationEngine


@dataclass
class RuleOp:
    """A single rule operation parsed from .rule syntax."""
    code: str
    args: str = ""
    
    def apply(self, word: str, engine: MutationEngine) -> Iterator[str]:
        """Apply this operation to a word."""
        code = self.code
        
        if code == "l":
            yield word.lower()
        elif code == "u":
            yield word.upper()
        elif code == "c":
            if word:
                yield word[0].upper() + word[1:]
        elif code == "C":
            if word:
                yield word[0].lower() + word[1:].upper()
        elif code == "r":
            yield word[::-1]
        elif code == "d":
            yield word + word
        elif code == "f":
            yield word + word[::-1]
        elif code == "t":
            trans = str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
            yield word.translate(trans)
        elif code == "TN":
            yield word.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
        elif code == "TN":
            yield word.translate(str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        elif code == "[":  # Delete first char
            if len(word) > 1:
                yield word[1:]
        elif code == "]":  # Delete last char
            if len(word) > 1:
                yield word[:-1]
        elif code == "$":  # Append char
            yield word + self.args
        elif code == "^":  # Prepend char
            yield self.args + word
        elif code == "s":  # Substitute: sXY (replace X with Y)
            if len(self.args) >= 2:
                yield word.replace(self.args[0], self.args[1])
        elif code == "sa":  # Scrub (remove) char
            if self.args:
                yield word.replace(self.args[0], "")
        elif code == "D":  # Duplicate N times
            try:
                n = int(self.args) if self.args else 1
                yield word * (n + 1)
            except ValueError:
                yield word * 2
        elif code == "p":  # Duplicate first N chars
            try:
                n = int(self.args) if self.args else 1
                yield word + word[:n]
            except ValueError:
                yield word + word[:1]
        elif code == "P":  # Duplicate last N chars
            try:
                n = int(self.args) if self.args else 1
                yield word + word[-n:] if n <= len(word) else word + word
            except ValueError:
                yield word + word[-1:] if word else word
        elif code == "4":  # Overwrite at position
            parts = self.args.split()
            if len(parts) == 2:
                try:
                    pos, char = int(parts[0]), parts[1]
                    if pos < len(word):
                        yield word[:pos] + char + word[pos+1:]
                except ValueError:
                    pass
        elif code == "6":  # Overwrite at position from end
            parts = self.args.split()
            if len(parts) == 2:
                try:
                    pos, char = int(parts[0]), parts[1]
                    real_pos = len(word) - 1 - pos
                    if 0 <= real_pos < len(word):
                        yield word[:real_pos] + char + word[real_pos+1:]
                except ValueError:
                    pass
        elif code == "x":  # Extract substring: xSTART LEN
            parts = self.args.split()
            if len(parts) == 2:
                try:
                    start, length = int(parts[0]), int(parts[1])
                    yield word[start:start+length]
                except ValueError:
                    pass
        elif code == "i":  # Insert at position: iPOS CHAR
            parts = self.args.split()
            if len(parts) == 2:
                try:
                    pos, char = int(parts[0]), parts[1]
                    yield word[:pos] + char + word[pos:]
                except ValueError:
                    pass
        elif code == "o":  # Overwrite with section from another word (skip for now)
            pass
        elif code == "'":  # Truncate at position
            try:
                pos = int(self.args) if self.args else 0
                if pos < len(word):
                    yield word[:pos]
            except ValueError:
                pass
        elif code == "z":  # Duplicate first char N times
            try:
                n = int(self.args) if self.args else 1
                if word:
                    yield word[0] * n + word
            except ValueError:
                pass
        elif code == "Z":  # Duplicate last char N times
            try:
                n = int(self.args) if self.args else 1
                if word:
                    yield word + word[-1] * n
            except ValueError:
                    pass
        elif code == "q":  # Toggle case of char at position
            try:
                pos = int(self.args) if self.args else 0
                if pos < len(word):
                    c = word[pos]
                    new_c = c.upper() if c.islower() else c.lower()
                    yield word[:pos] + new_c + word[pos+1:]
            except ValueError:
                pass
        elif code == "X":  # Extract and append: xSTART LEN
            parts = self.args.split()
            if len(parts) == 2:
                try:
                    start, length = int(parts[0]), int(parts[1])
                    yield word + word[start:start+length]
                except ValueError:
                    pass
        elif code == "M":  # Memory word (skip, complex)
            yield word
        elif code == "V":  # Overwrite with memory word (skip)
            yield word
        elif code == "1":  # Reject word unless it contains char
            if self.args and self.args[0] not in word:
                return
            yield word
        elif code == "2":  # Reject word unless it starts with char
            if self.args and not word.startswith(self.args[0]):
                return
            yield word
        elif code == "3":  # Reject word unless it ends with char
            if self.args and not word.endswith(self.args[0]):
                return
            yield word
        elif code == "@":  # Reject word unless length equals
            try:
                length = int(self.args) if self.args else 0
                if len(word) != length:
                    return
            except ValueError:
                return
            yield word
        elif code == "!" or code == "/":  # Reject word if it contains char
            if self.args and self.args[0] in word:
                return
            yield word
        elif code == ">":  # Reject if length > N
            try:
                n = int(self.args) if self.args else 0
                if len(word) > n:
                    return
            except ValueError:
                return
            yield word
        elif code == "<":  # Reject if length < N
            try:
                n = int(self.args) if self.args else 0
                if len(word) < n:
                    return
            except ValueError:
                return
            yield word
        else:
            yield word


class RuleFileParser:
    """Parse John the Ripper .rule format files."""
    
    def __init__(self):
        self._rules: List[List[RuleOp]] = []
    
    def parse_file(self, filepath: str) -> List[List[RuleOp]]:
        """Parse a .rule file and return list of rule chains."""
        self._rules.clear()
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                chain = self._parse_line(line)
                if chain:
                    self._rules.append(chain)
        return self._rules
    
    def parse_string(self, content: str) -> List[List[RuleOp]]:
        """Parse rules from a string."""
        self._rules.clear()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            chain = self._parse_line(line)
            if chain:
                self._rules.append(chain)
        return self._rules
    
    def _parse_line(self, line: str) -> List[RuleOp]:
        """Parse a single rule line into a chain of operations."""
        ops = []
        i = 0
        while i < len(line):
            # Skip whitespace
            if line[i] in (' ', '\t'):
                i += 1
                continue
            
            # Check for two-char operations
            if i + 1 < len(line):
                two = line[i:i+2]
                if two in ('sa', 's"', 's[', 's]', 's{', 's}', 's(', 's)', 's<', 's>', 's/', 's\\', 's=', 's.', 's!', 's@', 's#', 's$', 's%', 's^', 's&', 's*', 's-', 's+', 's~', 's`', 's|', 's?', 's:', "s'", 's,', 's_', 's;', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9'):
                    if i + 2 < len(line):
                        ops.append(RuleOp(two, line[i+2]))
                        i += 3
                    else:
                        ops.append(RuleOp(two))
                        i += 2
                    continue
            
            char = line[i]
            
            # Operations that take arguments
            if char in ('$^sSDpP46xiqX@!/> <Zz'):
                if i + 1 < len(line):
                    # Find the argument (next non-space token or single char)
                    j = i + 1
                    if j < len(line) and line[j] == ' ':
                        j += 1
                    # For substitution, take next 2 chars
                    if char == 's' and j + 1 < len(line):
                        ops.append(RuleOp(char, line[j:j+2]))
                        i = j + 2
                    elif char in ('D', 'p', 'P', 'Z', 'z', '@', '>', '<', "'", 'x', 'X'):
                        # Take next token (number or two numbers)
                        arg_start = j
                        while j < len(line) and line[j] not in (' ', '\t', ':', ';'):
                            j += 1
                        ops.append(RuleOp(char, line[arg_start:j]))
                        i = j
                    elif char in ('4', '6', 'i'):
                        # Take "pos char"
                        arg_start = j
                        while j < len(line) and line[j] not in (' ', '\t'):
                            j += 1
                        pos_part = line[arg_start:j]
                        if j < len(line) and line[j] == ' ':
                            j += 1
                        char_start = j
                        while j < len(line) and line[j] not in (' ', '\t', ':', ';'):
                            j += 1
                        ops.append(RuleOp(char, pos_part + ' ' + line[char_start:j]))
                        i = j
                    else:
                        arg_start = j
                        while j < len(line) and line[j] not in (' ', '\t', ':', ';'):
                            j += 1
                        ops.append(RuleOp(char, line[arg_start:j]))
                        i = j
                else:
                    ops.append(RuleOp(char))
                    i += 1
            else:
                ops.append(RuleOp(char))
                i += 1
        
        return ops
    
    def apply_rules(self, word: str, rules: Optional[List[List[RuleOp]]] = None) -> Iterator[str]:
        """Apply all rules to a word."""
        engine = MutationEngine()
        rule_chains = rules or self._rules
        
        for chain in rule_chains:
            candidates = [word]
            for op in chain:
                next_candidates = []
                for c in candidates:
                    next_candidates.extend(op.apply(c, engine))
                candidates = next_candidates
            yield from candidates
    
    @property
    def rule_count(self) -> int:
        return len(self._rules)
    
    def __repr__(self) -> str:
        return f"RuleFileParser(rules={self.rule_count})"
