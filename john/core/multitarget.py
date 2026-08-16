"""Multi-target mode for cross-referencing multiple hash files."""

from typing import List, Dict, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from ..hashes.detector import HashDetector
from ..hashes.parser import HashParser, ParseOptions
from ..hashes.algorithms.base import HashInfo


@dataclass
class MultiTargetConfig:
    """Configuration for multi-target audit."""
    hash_files: List[str]
    combine: bool = False  # Cross-reference all files
    intersect: bool = False  # Find passwords common to multiple targets
    format_override: Optional[str] = None


@dataclass
class TargetGroup:
    """A group of hashes from one or more files."""
    source_files: List[str]
    hash_infos: List[HashInfo] = field(default_factory=list)
    format_breakdown: Dict[str, int] = field(default_factory=dict)
    
    @property
    def total_hashes(self) -> int:
        return len(self.hash_infos)
    
    @property
    def primary_format(self) -> Optional[str]:
        if not self.format_breakdown:
            return None
        return max(self.format_breakdown, key=self.format_breakdown.get)


class MultiTargetManager:
    """Manages multiple hash file targets for combined auditing."""
    
    def __init__(self):
        self.detector = HashDetector()
        self.parser = HashParser(self.detector)
        self._targets: Dict[str, TargetGroup] = {}
    
    def load_targets(self, config: MultiTargetConfig) -> Dict[str, TargetGroup]:
        """Load and organize multiple hash files."""
        self._targets.clear()
        
        for filepath in config.hash_files:
            path = Path(filepath)
            if not path.exists():
                continue
            
            parse_options = ParseOptions(format_override=config.format_override)
            hash_infos = self.parser.parse_file(filepath, parse_options)
            
            # Group by detected format
            format_counts = {}
            for hi in hash_infos:
                fmt = hi.format_name.lower()
                format_counts[fmt] = format_counts.get(fmt, 0) + 1
            
            group = TargetGroup(
                source_files=[filepath],
                hash_infos=hash_infos,
                format_breakdown=format_counts,
            )
            
            self._targets[filepath] = group
        
        return self._targets
    
    def get_combined_hashes(self) -> List[HashInfo]:
        """Get all hashes from all targets combined."""
        combined = []
        for group in self._targets.values():
            combined.extend(group.hash_infos)
        return combined
    
    def get_format_summary(self) -> Dict[str, int]:
        """Get aggregate format counts across all targets."""
        combined = {}
        for group in self._targets.values():
            for fmt, count in group.format_breakdown.items():
                combined[fmt] = combined.get(fmt, 0) + count
        return combined
    
    def find_common_hashes(self) -> Dict[str, List[str]]:
        """Find hash values that appear in multiple targets."""
        hash_to_files = {}
        for filepath, group in self._targets.items():
            for hi in group.hash_infos:
                key = hi.hash_value.lower()
                if key not in hash_to_files:
                    hash_to_files[key] = []
                hash_to_files[key].append(filepath)
        
        return {h: files for h, files in hash_to_files.items() if len(files) > 1}
    
    def get_target_info(self) -> List[Dict]:
        """Get info about each loaded target."""
        return [
            {
                "file": fp,
                "hashes": group.total_hashes,
                "formats": group.format_breakdown,
                "primary_format": group.primary_format,
            }
            for fp, group in self._targets.items()
        ]
    
    @property
    def total_targets(self) -> int:
        return len(self._targets)
    
    @property
    def total_hashes(self) -> int:
        return sum(g.total_hashes for g in self._targets.values())
