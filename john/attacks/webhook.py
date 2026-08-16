"""Webhook notification system for match alerts."""

import json
import time
import threading
from typing import Optional, Dict, Any, List
from urllib.request import Request, urlopen
from urllib.error import URLError
from dataclasses import dataclass, field


@dataclass
class WebhookConfig:
    """Configuration for webhook notifications."""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    on_match: bool = True
    on_complete: bool = True
    on_error: bool = True
    batch_size: int = 1  # Send individual or batched notifications
    retry_count: int = 3
    retry_delay: float = 1.0
    timeout: float = 5.0


@dataclass
class WebhookEvent:
    """A webhook event to send."""
    event_type: str  # match, complete, error, progress
    timestamp: float
    data: Dict[str, Any]
    sent: bool = False


class WebhookNotifier:
    """Send notifications via webhooks on match/error/completion."""
    
    def __init__(self, configs: Optional[List[WebhookConfig]] = None):
        self._configs = configs or []
        self._queue: List[WebhookEvent] = []
        self._lock = threading.Lock()
        self._sender_thread: Optional[threading.Thread] = None
        self._running = False
        self._stats = {"sent": 0, "failed": 0}
    
    def add_webhook(self, config: WebhookConfig):
        """Add a webhook endpoint."""
        self._configs.append(config)
    
    def start(self):
        """Start the background sender thread."""
        self._running = True
        self._sender_thread = threading.Thread(target=self._send_loop, daemon=True)
        self._sender_thread.start()
    
    def stop(self):
        """Stop the sender and flush remaining events."""
        self._running = False
        if self._sender_thread:
            self._sender_thread.join(timeout=5)
        self._flush()
    
    def notify_match(self, candidate: str, hash_value: str, format_name: str,
                     strategy: str, session_id: str = ""):
        """Send a match notification."""
        event = WebhookEvent(
            event_type="match",
            timestamp=time.time(),
            data={
                "event": "password_found",
                "password": candidate,
                "hash": hash_value[:40] + "..." if len(hash_value) > 40 else hash_value,
                "format": format_name,
                "strategy": strategy,
                "session_id": session_id,
            }
        )
        self._queue_event(event)
    
    def notify_complete(self, session_id: str, total_tested: int, matches: int, elapsed: float):
        """Send completion notification."""
        event = WebhookEvent(
            event_type="complete",
            timestamp=time.time(),
            data={
                "event": "audit_complete",
                "session_id": session_id,
                "candidates_tested": total_tested,
                "matches_found": matches,
                "elapsed_seconds": round(elapsed, 2),
            }
        )
        self._queue_event(event)
    
    def notify_error(self, error: str, session_id: str = ""):
        """Send error notification."""
        event = WebhookEvent(
            event_type="error",
            timestamp=time.time(),
            data={
                "event": "audit_error",
                "error": error,
                "session_id": session_id,
            }
        )
        self._queue_event(event)
    
    def notify_progress(self, session_id: str, tested: int, matches: int, rate: float):
        """Send progress notification."""
        event = WebhookEvent(
            event_type="progress",
            timestamp=time.time(),
            data={
                "event": "progress_update",
                "session_id": session_id,
                "candidates_tested": tested,
                "matches": matches,
                "rate_hps": round(rate, 1),
            }
        )
        self._queue_event(event)
    
    def _queue_event(self, event: WebhookEvent):
        """Queue an event for sending."""
        with self._lock:
            self._queue.append(event)
    
    def _send_loop(self):
        """Background loop to send queued events."""
        while self._running:
            with self._lock:
                events = list(self._queue)
                self._queue.clear()
            
            for event in events:
                self._send_event(event)
            
            time.sleep(0.5)
    
    def _flush(self):
        """Send all remaining queued events."""
        with self._lock:
            events = list(self._queue)
            self._queue.clear()
        
        for event in events:
            self._send_event(event)
    
    def _send_event(self, event: WebhookEvent):
        """Send an event to all configured webhooks."""
        for config in self._configs:
            # Check if this event type should be sent
            if event.event_type == "match" and not config.on_match:
                continue
            if event.event_type == "complete" and not config.on_complete:
                continue
            if event.event_type == "error" and not config.on_error:
                continue
            
            payload = json.dumps({
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "data": event.data,
            }).encode('utf-8')
            
            for attempt in range(config.retry_count):
                try:
                    req = Request(
                        config.url,
                        data=payload,
                        headers=config.headers,
                        method=config.method,
                    )
                    with urlopen(req, timeout=config.timeout) as resp:
                        if resp.status < 400:
                            self._stats["sent"] += 1
                            event.sent = True
                            break
                except (URLError, OSError, Exception):
                    if attempt < config.retry_count - 1:
                        time.sleep(config.retry_delay * (attempt + 1))
                    else:
                        self._stats["failed"] += 1
    
    @property
    def stats(self) -> dict:
        return self._stats.copy()
    
    @property
    def is_configured(self) -> bool:
        return len(self._configs) > 0
