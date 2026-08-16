"""Task scheduler for parallel attack execution."""

import threading
import queue
import time
from typing import Optional, Callable, List, Any
from dataclasses import dataclass, field


@dataclass
class Task:
    """A schedulable task."""
    task_id: str
    func: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    priority: int = 0
    result: Any = None
    error: Optional[Exception] = None
    completed: bool = False


class TaskScheduler:
    """Manages parallel task execution with bounded queues."""
    
    def __init__(self, max_workers: int = 4, queue_size: int = 10000):
        self.max_workers = max_workers
        self.queue_size = queue_size
        self._task_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._result_queue: queue.Queue = queue.Queue()
        self._workers: List[threading.Thread] = []
        self._running = False
        self._lock = threading.Lock()
        self._completed_tasks = 0
        self._failed_tasks = 0
    
    def start(self):
        """Start worker threads."""
        self._running = True
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"worker-{i}",
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)
    
    def stop(self):
        """Stop all workers."""
        self._running = False
        # Send poison pills
        for _ in range(self.max_workers):
            self._task_queue.put(None)
        for worker in self._workers:
            worker.join(timeout=5)
        self._workers.clear()
    
    def submit(self, task: Task):
        """Submit a task for execution."""
        self._task_queue.put(task)
    
    def get_result(self, timeout: float = 1.0) -> Optional[Task]:
        """Get a completed task result."""
        try:
            return self._result_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def _worker_loop(self):
        """Worker thread main loop."""
        while self._running:
            try:
                task = self._task_queue.get(timeout=1)
                if task is None:
                    break
                
                try:
                    task.result = task.func(*task.args, **task.kwargs)
                    task.completed = True
                    with self._lock:
                        self._completed_tasks += 1
                except Exception as e:
                    task.error = e
                    with self._lock:
                        self._failed_tasks += 1
                finally:
                    self._result_queue.put(task)
                    self._task_queue.task_done()
            except queue.Empty:
                continue
    
    @property
    def stats(self) -> dict:
        return {
            "workers": self.max_workers,
            "completed": self._completed_tasks,
            "failed": self._failed_tasks,
            "queue_size": self._task_queue.qsize(),
        }
