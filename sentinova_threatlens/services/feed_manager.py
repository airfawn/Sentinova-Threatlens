from __future__ import annotations

import logging
from typing import Any

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.compliance import ComplianceRepository
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.normalizer import Normalizer
from sentinova_threatlens.services.scheduler import FeedScheduler
from sentinova_threatlens.sources import ALL_SOURCES
from sentinova_threatlens.services.taxii import Taxii21Client

logger = logging.getLogger(__name__)


class FeedManager:
    def __init__(self, config: AppConfig, db: DatabaseEngine) -> None:
        self._config = config
        self._db = db
        self._repo = ComplianceRepository(db)
        self._normalizer = Normalizer()
        self._classes = {source.name: source for source in ALL_SOURCES}
        self._scheduler = FeedScheduler(self._feeds, self._poll, self._health)

    def start(self) -> None:
        self._scheduler.start()

    def stop(self) -> None:
        self._scheduler.stop()

    def poll_now(self, feed_id: int) -> None:
        feed = self._repo.feed(feed_id)
        if not feed:
            raise LookupError("Feed not found")
        self._scheduler.poll_now(feed[0])

    def _feeds(self) -> list[dict[str, Any]]:
        try:
            return self._repo.feeds()
        except Exception:
            return []

    def _poll(self, feed: dict[str, Any]) -> None:
        if str(feed.get("source_type")) == "taxii":
            client = Taxii21Client(str(feed["endpoint"]), timeout=self._config.sources.request_timeout)
            objects, checkpoint = client.poll(str(feed["endpoint"]), feed.get("checkpoint"))
            records = []
            for raw in objects:
                value = raw.get("pattern", "")
                if value:
                    records.extend(self._normalizer.normalize("TAXII", {"value": value, "raw": raw}))
            if records:
                self._db.upsert_batch(records)
            self._repo._query("UPDATE cti_iocs.feed_registry SET checkpoint=%s,last_poll=NOW(),next_poll=NOW()+make_interval(secs => poll_interval_seconds) WHERE id=%s", (checkpoint, feed["id"]), write=True)
            return
        source_cls = self._classes.get(str(feed["name"]))
        if source_cls is None:
            raise ValueError(f"No adapter registered for {feed['name']}")
        source = source_cls(self._config.sources)
        try:
            raw_items = source.fetch()
            records = []
            for raw in raw_items:
                records.extend(self._normalizer.normalize(source.name, raw))
            if records:
                self._db.upsert_batch(records)
            self._repo._query("UPDATE cti_iocs.feed_registry SET last_poll=NOW(), next_poll=NOW() + make_interval(secs => poll_interval_seconds) WHERE id=%s", (feed["id"],), write=True)
        finally:
            source.close()

    def _health(self, feed: dict[str, Any], status: str, error: str) -> None:
        self._repo._query("UPDATE cti_iocs.feed_registry SET status=%s, failure_count=CASE WHEN %s='healthy' THEN 0 ELSE failure_count+1 END, settings=settings || %s::jsonb WHERE id=%s", (status, status, __import__("json").dumps({"last_error": error}), feed["id"]), write=True)