from __future__ import annotations

import threading
from typing import Callable


class ScanCancelledError(RuntimeError):
    """Raised when a user explicitly stops an in-flight scan."""


class ScanCancellationRegistry:
    """Tracks live scan sessions and their cancellation state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}
        self._active_jobs: dict[str, int] = {}

    def begin_job(self, session_id: str) -> None:
        with self._lock:
            self._events.setdefault(session_id, threading.Event())
            self._active_jobs[session_id] = self._active_jobs.get(session_id, 0) + 1

    def finish_job(self, session_id: str) -> None:
        with self._lock:
            current = self._active_jobs.get(session_id, 0)
            if current <= 1:
                self._active_jobs.pop(session_id, None)
                self._events.pop(session_id, None)
                return
            self._active_jobs[session_id] = current - 1

    def request_cancel(self, session_id: str) -> bool:
        with self._lock:
            event = self._events.setdefault(session_id, threading.Event())
            event.set()
            return True

    def is_cancelled(self, session_id: str) -> bool:
        with self._lock:
            event = self._events.get(session_id)
            return bool(event and event.is_set())

    def has_session(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._events or session_id in self._active_jobs

    def should_cancel(self, session_id: str) -> Callable[[], bool]:
        return lambda: self.is_cancelled(session_id)

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._events.pop(session_id, None)
            self._active_jobs.pop(session_id, None)
