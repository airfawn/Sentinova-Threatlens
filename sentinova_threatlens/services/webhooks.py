from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any

from sentinova_threatlens.compliance import verify_signature


class WebhookGuard:
    """Verify signed inbound events and reject replayed request identifiers."""

    def __init__(self, secret: str, replay_window_seconds: int = 300) -> None:
        self.secret = secret
        self.replay_window_seconds = replay_window_seconds
        self._seen: OrderedDict[str, float] = OrderedDict()

    def accept(self, body: bytes, signature: str, request_id: str, timestamp: float | None = None) -> bool:
        now = time.time()
        event_time = timestamp or now
        if abs(now - event_time) > self.replay_window_seconds or request_id in self._seen:
            return False
        if not verify_signature(body, signature, self.secret):
            return False
        self._seen[request_id] = now
        while self._seen and now - next(iter(self._seen.values())) > self.replay_window_seconds:
            self._seen.popitem(last=False)
        return True
