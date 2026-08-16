"""Additional CLI command implementations."""

from typing import Optional
from pathlib import Path


def format_size(size_bytes: int) -> str:
    """Format byte size to human readable."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def validate_hash_file(filepath: str) -> bool:
    """Validate a hash file exists and is readable."""
    path = Path(filepath)
    if not path.exists():
        return False
    if not path.is_file():
        return False
    try:
        with open(path, 'r') as f:
            f.read(1)
        return True
    except Exception:
        return False


def validate_wordlist(filepath: str) -> bool:
    """Validate a wordlist file."""
    return validate_hash_file(filepath)


def get_file_stats(filepath: str) -> dict:
    """Get basic file statistics."""
    path = Path(filepath)
    if not path.exists():
        return {"exists": False}
    
    stat = path.stat()
    return {
        "exists": True,
        "size": stat.st_size,
        "size_human": format_size(stat.st_size),
        "modified": stat.st_mtime,
    }
