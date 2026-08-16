"""Worker pool for parallel hash computation."""

import threading
import queue
from typing import Callable, List, Any, Optional
from dataclasses import dataclass


@dataclass
class WorkerTask:
    task_id: int
    data: Any
    func: Callable


class WorkerPool:
    def __init__(self, num_workers: Optional[int] = None):
        import os
        self.num_workers = num_workers or os.cpu_count() or 4
        self._task_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._result_queue: queue.Queue = queue.Queue()
        self._workers: List[threading.Thread] = []
        self._running = False
        self._completed = 0
        self._failed = 0

    def start(self):
        self._running = True
        for _ in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._workers.append(t)

    def stop(self):
        self._running = False
        for _ in range(self.num_workers):
            self._task_queue.put(None)
        for t in self._workers:
            t.join(timeout=5)
        self._workers.clear()

    def submit(self, task: WorkerTask):
        self._task_queue.put(task)

    def get_result(self, timeout: float = 1.0) -> Optional[WorkerTask]:
        try:
            return self._result_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _worker_loop(self):
        while self._running:
            try:
                task = self._task_queue.get(timeout=1)
                if task is None:
                    break
                try:
                    task.data = task.func(task.data)
                    self._completed += 1
                except Exception:
                    self._failed += 1
                finally:
                    self._result_queue.put(task)
                    self._task_queue.task_done()
            except queue.Empty:
                continue

    @property
    def stats(self) -> dict:
        return {
            "workers": self.num_workers,
            "completed": self._completed,
            "failed": self._failed,
            "queue_size": self._task_queue.qsize(),
        }
