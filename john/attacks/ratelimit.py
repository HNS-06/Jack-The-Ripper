"""Rate limiting for controlled attack speed."""

import time
from typing import Iterator


class RateLimiter:
    """Token bucket rate limiter for attack throughput control."""
    
    def __init__(self, rate: int = 0):
        self.rate = rate  # 0 = unlimited
        self._tokens = 0.0
        self._last_refill = time.monotonic()
        self._total_waited = 0.0
    
    def acquire(self):
        if self.rate <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
        self._last_refill = now
        
        if self._tokens < 1:
            wait = (1 - self._tokens) / self.rate
            self._total_waited += wait
            time.sleep(wait)
            self._tokens = 0
        else:
            self._tokens -= 1
    
    def throttle(self, stream: Iterator) -> Iterator:
        for item in stream:
            self.acquire()
            yield item
    
    @property
    def total_waited(self) -> float:
        return self._total_waited
    
    def __repr__(self) -> str:
        return f"RateLimiter(rate={self.rate}/s)"


class AdaptiveRateLimiter:
    """Rate limiter that auto-adjusts based on system load."""
    
    def __init__(self, initial_rate: int = 0, target_cpu: float = 80.0):
        self.current_rate = initial_rate
        self.target_cpu = target_cpu
        self._limiter = RateLimiter(initial_rate)
        self._adjust_interval = 5.0
        self._last_adjust = time.monotonic()
    
    def _get_cpu_usage(self) -> float:
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            import os
            if hasattr(os, 'getloadavg'):
                load = os.getloadavg()[0]
                cores = os.cpu_count() or 1
                return (load / cores) * 100
            return 50.0
    
    def maybe_adjust(self):
        now = time.monotonic()
        if now - self._last_adjust < self._adjust_interval:
            return
        self._last_adjust = now
        cpu = self._get_cpu_usage()
        if cpu > self.target_cpu + 10 and self.current_rate > 100:
            self.current_rate = int(self.current_rate * 0.8)
            self._limiter.rate = self.current_rate
        elif cpu < self.target_cpu - 10:
            self.current_rate = int(self.current_rate * 1.2)
            self._limiter.rate = self.current_rate
    
    def throttle(self, stream: Iterator) -> Iterator:
        for item in stream:
            self.maybe_adjust()
            self._limiter.acquire()
            yield item
