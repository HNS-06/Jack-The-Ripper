"""Piped input support for pipeline integration."""

import sys
import select
from typing import Iterator, Optional, IO
from pathlib import Path


class PipedInput:
    """Handle piped stdin input for hash processing."""
    
    def __init__(self):
        self._source: Optional[str] = None
        self._is_piped = False
    
    def detect(self) -> bool:
        """Detect if input is being piped."""
        if sys.platform == "win32":
            try:
                import msvcrt
                return False
            except ImportError:
                return False
        else:
            return not sys.stdin.isatty()
    
    def read_lines(self, source: Optional[str] = None) -> Iterator[str]:
        """Read lines from piped input or file."""
        if source and source != "-":
            # File input
            path = Path(source)
            if path.exists():
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        yield line.rstrip('\n\r')
        else:
            # Stdin input
            for line in sys.stdin:
                yield line.rstrip('\n\r')
    
    def read_hashes(self, source: Optional[str] = None) -> Iterator[str]:
        """Read hashes from input, filtering empty/comment lines."""
        for line in self.read_lines(source):
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            yield line
    
    def read_wordlist(self, source: Optional[str] = None) -> Iterator[str]:
        """Read words from input as a wordlist."""
        yield from self.read_hashes(source)
    
    def create_temp_wordlist(self, words: Iterator[str], output_path: str = None) -> str:
        """Write piped words to a temp wordlist file."""
        import tempfile
        
        if output_path is None:
            fd, output_path = tempfile.mkstemp(suffix='.txt', prefix='john_pipe_')
            import os
            os.close(fd)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for word in words:
                f.write(word + '\n')
        
        return output_path
    
    def pipe_hashcat_output(self, hashcat_cmd: str) -> Iterator[str]:
        """Parse output from hashcat or similar tools piped to john."""
        import subprocess
        import shlex
        
        try:
            proc = subprocess.Popen(
                shlex.split(hashcat_cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            for line in proc.stdout:
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    # Parse hashcat output format: hash:password
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        yield parts[0]
            
            proc.wait()
        except Exception:
            pass
