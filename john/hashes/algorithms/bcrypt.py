"""bcrypt hash algorithm implementation."""

import re
from typing import Optional
from .base import HashAlgorithm, HashInfo


class BcryptAlgorithm(HashAlgorithm):
    name = "bcrypt"
    format_id = "bcrypt"
    hash_length = 60
    patterns = [
        r'^\$2[aby]?\$\d{2}\$[A-Za-z0-9./]{53}$',
    ]

    def identify(self, hash_str: str) -> float:
        cleaned = hash_str.strip()
        if re.match(r'^\$2[aby]?\$\d{2}\$', cleaned):
            return 0.99
        return 0.0

    def verify(self, candidate: str, hash_info: HashInfo) -> bool:
        try:
            import bcrypt
            return bcrypt.checkpw(
                candidate.encode('utf-8'),
                hash_info.original_line.strip().encode('utf-8')
            )
        except ImportError:
            return self._fallback_verify(candidate, hash_info)

    def _fallback_verify(self, candidate: str, hash_info: HashInfo) -> bool:
        """Fallback using subprocess if bcrypt library unavailable."""
        import subprocess
        import tempfile
        import os
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(candidate)
                candidate_file = f.name
            result = subprocess.run(
                ['python', '-c', f'''
import bcrypt
with open("{candidate_file}") as f:
    pw = f.read().strip()
print(bcrypt.checkpw(pw.encode(), b"{hash_info.original_line.strip()}"))
'''],
                capture_output=True, text=True, timeout=5
            )
            return 'True' in result.stdout
        except Exception:
            return False
        finally:
            try:
                os.unlink(candidate_file)
            except Exception:
                pass

    def hash(self, password: str, salt: Optional[str] = None) -> str:
        try:
            import bcrypt
            if salt:
                return bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')
            return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        except ImportError:
            raise RuntimeError("bcrypt library required. Install with: pip install bcrypt")
