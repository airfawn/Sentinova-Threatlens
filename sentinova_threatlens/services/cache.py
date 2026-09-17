from __future__ import annotations

import json
import logging
from typing import Any

from sentinova_threatlens.config import RedisConfig

logger = logging.getLogger(__name__)


class RedisCache:
    """Best-effort Redis cache/pub-sub adapter with an offline no-op mode."""

    def __init__(self, config: RedisConfig) -> None:
        self._config = config
        self._client: Any = None
        self._local: dict[str, Any] = {}
        if not config.enabled:
            return
        try:
            import redis

            self._client = redis.Redis.from_url(config.url, decode_responses=True)
            self._client.ping()
        except Exception:
            logger.info("Redis unavailable; continuing with in-process cache", exc_info=True)
            self._client = None

    def get_json(self, key: str) -> Any:
        if self._client is not None:
            try:
                value = self._client.get(key)
                return json.loads(value) if value else None
            except Exception:
                logger.debug("Redis read failed for %s", key, exc_info=True)
        return self._local.get(key)

    def set_json(self, key: str, value: Any, ttl: int | None = None) -> None:
        self._local[key] = value
        if self._client is not None:
            try:
                self._client.setex(key, ttl or self._config.ttl_seconds, json.dumps(value, default=str))
            except Exception:
                logger.debug("Redis write failed for %s", key, exc_info=True)

    def publish(self, channel: str, payload: dict[str, Any]) -> int:
        if self._client is None:
            return 0
        try:
            return int(self._client.publish(channel, json.dumps(payload, default=str)))
        except Exception:
            logger.debug("Redis publish failed for %s", channel, exc_info=True)
            return 0
