"""Secure cleanup of sensitive data."""

import os
import gc
import tempfile
from pathlib import Path


class SecureCleanup:
    @staticmethod
    def wipe_file(filepath: str, passes: int = 3):
        path = Path(filepath)
        if not path.exists():
            return
        size = path.stat().st_size
        with open(path, 'wb') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()

    @staticmethod
    def clear_string(s: str) -> str:
        return ""

    @staticmethod
    def clear_list(lst: list):
        lst.clear()
        gc.collect()

    @staticmethod
    def cleanup_session_files(session_dir: str):
        path = Path(session_dir)
        if path.exists():
            for f in path.glob("*.tmp"):
                f.unlink()

    @staticmethod
    def cleanup_temp_files():
        temp_dir = Path(tempfile.gettempdir())
        for f in temp_dir.glob("john_*"):
            try:
                f.unlink()
            except Exception:
                pass
