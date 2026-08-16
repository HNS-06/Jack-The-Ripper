"""Input validation and sanitization."""

import re
from pathlib import Path


class InputValidator:
    @staticmethod
    def validate_hash_file(filepath: str) -> tuple:
        if not filepath:
            return False, "Empty file path"
        path = Path(filepath)
        if not path.exists():
            return False, f"File not found: {filepath}"
        if not path.is_file():
            return False, f"Not a regular file: {filepath}"
        if path.stat().st_size == 0:
            return False, f"Empty file: {filepath}"
        if path.stat().st_size > 10 * 1024 * 1024 * 1024:
            return False, f"File too large: {filepath}"
        return True, "Valid"

    @staticmethod
    def validate_wordlist(filepath: str) -> tuple:
        return InputValidator.validate_hash_file(filepath)

    @staticmethod
    def validate_mask(mask: str) -> tuple:
        if not mask:
            return False, "Empty mask"
        valid_masks = {'?l', '?u', '?d', '?s', '?a', '?b'}
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                key = mask[i:i+2]
                if key not in valid_masks:
                    return False, f"Invalid mask token: {key}"
                i += 2
            else:
                i += 1
        return True, "Valid"

    @staticmethod
    def validate_format(fmt: str) -> tuple:
        if not fmt:
            return False, "Empty format"
        if not re.match(r'^[a-zA-Z0-9_-]+$', fmt):
            return False, f"Invalid format name: {fmt}"
        return True, "Valid"

    @staticmethod
    def sanitize_path(filepath: str) -> str:
        return str(Path(filepath).resolve())
