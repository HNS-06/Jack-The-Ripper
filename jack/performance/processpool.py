"""Process pool workers for true parallelism bypassing GIL."""

import os
import time
from typing import List, Callable, Any, Optional
from multiprocessing import Process, Queue, cpu_count
from dataclasses import dataclass


@dataclass
class PoolTask:
    task_id: int
    args: tuple = ()
    kwargs: dict = None

    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}


class ProcessPool:
    """Process pool for CPU-bound hash computation bypassing GIL."""

    def __init__(self, num_workers: Optional[int] = None):
        self.num_workers = num_workers or cpu_count() or 4
        self._task_queue: Queue = Queue(maxsize=100000)
        self._result_queue: Queue = Queue()
        self._workers: List[Process] = []
        self._running = False
        self._completed = 0
        self._failed = 0

    def start(self, worker_func: Callable):
        self._running = True
        for _ in range(self.num_workers):
            p = Process(
                target=self._worker_loop,
                args=(worker_func, self._task_queue, self._result_queue),
                daemon=True,
            )
            p.start()
            self._workers.append(p)

    def stop(self):
        self._running = False
        for _ in range(self.num_workers):
            self._task_queue.put(None)
        for p in self._workers:
            p.join(timeout=10)
            if p.is_alive():
                p.terminate()
        self._workers.clear()

    def submit(self, task_id: int, args: tuple = (), kwargs: dict = None):
        self._task_queue.put(PoolTask(task_id=task_id, args=args, kwargs=kwargs or {}))

    def get_result(self, timeout: float = 1.0) -> Optional[tuple]:
        try:
            return self._result_queue.get(timeout=timeout)
        except Exception:
            return None

    @staticmethod
    def _worker_loop(func: Callable, task_queue: Queue, result_queue: Queue):
        while True:
            try:
                task = task_queue.get(timeout=2)
                if task is None:
                    break
                try:
                    result = func(*task.args, **task.kwargs)
                    result_queue.put((task.task_id, result, None))
                except Exception as e:
                    result_queue.put((task.task_id, None, str(e)))
            except Exception:
                continue

    @property
    def stats(self) -> dict:
        return {"workers": self.num_workers, "completed": self._completed, "failed": self._failed}


def hash_batch_worker(candidates, algorithm, hash_func_name):
    """Worker function for batch hashing in a subprocess."""
    import hashlib
    results = []
    for candidate in candidates:
        try:
            h = hashlib.new(algorithm, candidate.encode('utf-8')).hexdigest()
            results.append((candidate, h))
        except Exception:
            continue
    return results
