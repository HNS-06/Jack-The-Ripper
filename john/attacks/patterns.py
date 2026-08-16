"""Pattern-based attack module."""

from typing import Iterator, List
from itertools import product
from .base import AttackBase, AttackConfig
import string


# Common password patterns
COMMON_PATTERNS = [
    # Keyboard patterns
    ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx'],
    # Number patterns
    ['123456', '123456789', '12345678', '12345', '1234', '123'],
    # Common words
    ['password', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
     'master', 'qwerty', 'login', 'abc123', 'iloveyou', 'sunshine',
     'princess', 'football', 'charlie', 'shadow', 'michael', 'qwerty123'],
    # Leet variations
    ['p@ssw0rd', 'p@ssword', 'pa$$w0rd', 'passw0rd', 'p@ss'],
]


class PatternAttack(AttackBase):
    """Pattern-based attack using common password patterns."""
    
    name = "pattern"
    description = "Common pattern-based audit"
    
    def __init__(self, config: AttackConfig):
        super().__init__(config)
        self._custom_patterns = config.extra.get('patterns', [])
        self._include_common = config.extra.get('include_common', True)
        self._include_keyboard = config.extra.get('include_keyboard', True)
        self._include_dates = config.extra.get('include_dates', True)
    
    def generate_candidates(self) -> Iterator[str]:
        """Generate pattern-based candidates."""
        # Custom patterns first
        for pattern_group in self._custom_patterns:
            for word in pattern_group:
                yield word
        
        if self._include_common:
            for pattern_group in COMMON_PATTERNS:
                for word in pattern_group:
                    yield word
        
        if self._include_keyboard:
            yield from self._keyboard_patterns()
        
        if self._include_dates:
            yield from self._date_patterns()
    
    def _keyboard_patterns(self) -> Iterator[str]:
        """Generate keyboard walking patterns."""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890',
        ]
        
        for row in keyboard_rows:
            # Forward sequences
            for length in range(3, min(8, len(row) + 1)):
                for i in range(len(row) - length + 1):
                    yield row[i:i + length]
            
            # Reverse sequences
            for length in range(3, min(8, len(row) + 1)):
                for i in range(len(row) - length + 1):
                    yield row[i:i + length][::-1]
            
            # Alternating hands
            if len(row) >= 4:
                for i in range(0, len(row) - 2, 2):
                    yield row[i] + row[i + 2] + row[i + 1] + row[i + 3] if i + 3 < len(row) else ''
    
    def _date_patterns(self) -> Iterator[str]:
        """Generate common date-based patterns."""
        # Years
        for year in range(1950, 2030):
            yield str(year)
        
        # Common date formats
        months = [f'{i:02d}' for i in range(1, 13)]
        days = [f'{i:02d}' for i in range(1, 32)]
        
        for month in months:
            for day in days[:12]:  # Limit
                yield f"{month}{day}"
                yield f"{day}{month}"
                yield f"{month}{day}12"
                yield f"12{month}{day}"
        
        # Common years with month/day
        for year in ['1990', '1991', '1992', '1993', '1994', '1995',
                      '1996', '1997', '1998', '1999', '2000', '2001',
                      '2002', '2003', '2004', '2005', '2006', '2007',
                      '2008', '2009', '2010', '2011', '2012', '2013',
                      '2014', '2015', '2016', '2017', '2018', '2019',
                      '2020', '2021', '2022', '2023', '2024', '2025']:
            for month in ['01', '06', '12']:
                for day in ['01', '15']:
                    yield f"{year}{month}{day}"
                    yield f"{month}{day}{year}"
