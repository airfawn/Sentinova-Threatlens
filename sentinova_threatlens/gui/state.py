from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QObject, Signal

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.db.compliance import ComplianceRepository
from sentinova_threatlens.services.feed_manager import FeedManager

logger = logging.getLogger(__name__)


class AppState(QObject):
    records_changed = Signal(object)
    sources_changed = Signal(object)
    feeds_changed = Signal(object)
    incidents_changed = Signal(object)
    error = Signal(str)

    def __init__(self, config: AppConfig, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._db = DatabaseEngine(config)
        self._repo = ComplianceRepository(self._db)
        self._feed_manager = FeedManager(config, self._db)
        self.records: list[dict[str, Any]] = []
        self.sources: list[dict[str, Any]] = []
        self.feeds: list[dict[str, Any]] = []
        self.incidents: list[dict[str, Any]] = []

    def refresh(self) -> None:
        try:
            self._db.connect()
            self.records = self._db.records_with_scores(limit=50000)
            self.sources = self._db.source_status()
            self.feeds = self._repo.feeds()
            self.incidents = self._repo.incidents()
            self.records_changed.emit(self.records)
            self.sources_changed.emit(self.sources)
            self.feeds_changed.emit(self.feeds)
            self.incidents_changed.emit(self.incidents)
        except Exception:
            logger.exception("State refresh failed")
            self.error.emit("Database unavailable")

    def close(self) -> None:
        self._feed_manager.stop()
        try:
            self._db.close()
        except Exception:
            logger.debug("State database close failed", exc_info=True)

    def poll_feed(self, feed_id: int) -> None:
        self._feed_manager.poll_now(feed_id)
        self.refresh()
