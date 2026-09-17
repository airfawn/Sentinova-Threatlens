from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


class FeedScheduler:
    """Independent feed poll scheduler with retry/backoff and health callbacks."""

    def __init__(self, feeds: Callable[[], list[dict[str, Any]]], poll: Callable[[dict[str, Any]], None], health: Callable[[dict[str, Any], str, str], None], clock: Callable[[], float] = time.monotonic) -> None:
        self._feeds = feeds
        self._poll = poll
        self._health = health
        self._clock = clock
        self._next: dict[int, float] = {}
        self._failures: dict[int, int] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="threatlens-feed-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def poll_now(self, feed: dict[str, Any]) -> None:
        self._poll_one(feed)

    def _run(self) -> None:
        while not self._stop.wait(1):
            now = self._clock()
            for feed in self._feeds():
                feed_id = int(feed["id"])
                if feed.get("enabled", True) and now >= self._next.get(feed_id, 0):
                    self._poll_one(feed)

    def _poll_one(self, feed: dict[str, Any]) -> None:
        feed_id = int(feed["id"])
        interval = max(1, int(feed.get("poll_interval_seconds", 3600)))
        try:
            self._poll(feed)
            self._failures[feed_id] = 0
            self._health(feed, "healthy", "")
            self._next[feed_id] = self._clock() + interval
        except Exception as exc:
            failures = self._failures.get(feed_id, 0) + 1
            self._failures[feed_id] = failures
            self._health(feed, "error", str(exc))
            self._next[feed_id] = self._clock() + min(interval, 60 * (2 ** min(failures, 6)))
            logger.exception("Feed %s poll failed", feed_id)


class ExpirationWorker:
    def __init__(self, expire: Callable[[], int], interval_seconds: int = 60) -> None:
        self._expire = expire
        self._interval = max(1, interval_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="threatlens-expiration", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._expire()
            except Exception:
                logger.exception("IOC expiration pass failed")
