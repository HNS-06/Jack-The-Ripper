"""Pipeline processing for candidate generation and verification."""

from typing import Iterator, Optional, Callable, List
from dataclasses import dataclass
import time


@dataclass
class PipelineStage:
    """A stage in the processing pipeline."""
    name: str
    process: Callable
    description: str = ""


class Pipeline:
    """Processes candidates through a series of stages."""
    
    def __init__(self):
        self._stages: List[PipelineStage] = []
        self._stats = {
            "total_input": 0,
            "total_output": 0,
            "elapsed": 0.0,
        }
    
    def add_stage(self, name: str, process: Callable, description: str = ""):
        """Add a processing stage."""
        self._stages.append(PipelineStage(name, process, description))
    
    def process(self, input_stream: Iterator) -> Iterator:
        """Process input through all stages."""
        start = time.time()
        stream = input_stream
        
        for stage in self._stages:
            stream = stage.process(stream)
        
        for item in stream:
            self._stats["total_output"] += 1
            yield item
        
        self._stats["elapsed"] = time.time() - start
    
    def get_stats(self) -> dict:
        return self._stats.copy()
    
    def list_stages(self) -> List[dict]:
        return [
            {"name": s.name, "description": s.description}
            for s in self._stages
        ]
