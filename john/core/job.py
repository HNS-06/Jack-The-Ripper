"""Job management for attack execution."""

import time
import uuid
from typing import Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class Job:
    """Represents a single audit job."""
    job_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    status: str = "pending"  # pending, running, completed, failed, cancelled
    config: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None
    result: Any = None
    
    def start(self):
        self.status = "running"
        self.started_at = time.time()
    
    def complete(self, result=None):
        self.status = "completed"
        self.completed_at = time.time()
        self.result = result
    
    def fail(self, error: str):
        self.status = "failed"
        self.error = error
        self.completed_at = time.time()
    
    def cancel(self):
        self.status = "cancelled"
        self.completed_at = time.time()
    
    @property
    def elapsed(self) -> float:
        if self.started_at:
            end = self.completed_at or time.time()
            return end - self.started_at
        return 0.0
    
    @property
    def is_active(self) -> bool:
        return self.status in ("pending", "running")


class JobManager:
    """Manages multiple audit jobs."""
    
    def __init__(self):
        self._jobs: Dict[str, Job] = {}
    
    def create(self, name: str = "", config: dict = None) -> Job:
        job = Job(name=name, config=config or {})
        self._jobs[job.job_id] = job
        return job
    
    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)
    
    def list_jobs(self) -> list:
        return list(self._jobs.values())
    
    def active_jobs(self) -> list:
        return [j for j in self._jobs.values() if j.is_active]
