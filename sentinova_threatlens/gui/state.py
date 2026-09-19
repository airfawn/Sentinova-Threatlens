from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QThread, QObject, Signal

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.db.compliance import ComplianceRepository
from sentinova_threatlens.services.feed_manager import FeedManager

logger = logging.getLogger(__name__)


class _RefreshWorker(QThread):
    completed = Signal(object, object, object)
    failed = Signal(str)

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self._config = config

    def run(self) -> None:
        db = DatabaseEngine(self._config)
        try:
            db.connect()
            records = db.records_with_scores(limit=50000)
            sources = db.source_status()
            repo = ComplianceRepository(db)
            try:
                feeds = repo.feeds()
            except Exception:
                feeds = []
            try:
                incidents = repo.incidents()
            except Exception:
                incidents = []
            self.completed.emit(records, sources, (feeds, incidents))
        except Exception as exc:
            logger.exception("Background state refresh failed")
            self.failed.emit(str(exc))
        finally:
            db.close()


class AppState(QObject):
    records_changed = Signal(object)
    sources_changed = Signal(object)
    feeds_changed = Signal(object)
    incidents_changed = Signal(object)
    error = Signal(str)

    def __init__(self, config: AppConfig, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._db = DatabaseEngine(config)
        self._config = config
        self._repo = ComplianceRepository(self._db)
        self._feed_manager = FeedManager(config, self._db)
        self.records: list[dict[str, Any]] = []
        self.sources: list[dict[str, Any]] = []
        self.feeds: list[dict[str, Any]] = []
        self.incidents: list[dict[str, Any]] = []
        self._refresh_worker: _RefreshWorker | None = None

    def refresh(self) -> None:
        if self._refresh_worker is not None and self._refresh_worker.isRunning():
            return

        self._refresh_worker = _RefreshWorker(self._config)
        self._refresh_worker.completed.connect(self._on_refresh_completed)
        self._refresh_worker.failed.connect(self._on_refresh_failed)
        self._refresh_worker.finished.connect(self._refresh_worker.deleteLater)
        self._refresh_worker.start()

    def _on_refresh_completed(self, records: object, sources: object, extras: object) -> None:
        self.records = records if isinstance(records, list) else []
        self.sources = sources if isinstance(sources, list) else []
        feeds, incidents = extras if isinstance(extras, tuple) else ([], [])
        self.feeds = feeds if isinstance(feeds, list) else []
        self.incidents = incidents if isinstance(incidents, list) else []
        try:
            self.records_changed.emit(self.records)
            self.sources_changed.emit(self.sources)
            self.feeds_changed.emit(self.feeds)
            self.incidents_changed.emit(self.incidents)
        except RuntimeError:
            logger.debug("State widgets already destroyed", exc_info=True)

    def _on_refresh_failed(self, error: str) -> None:
        logger.error("State refresh failed: %s", error)
        self.error.emit("Database unavailable")

    def close(self) -> None:
        if self._refresh_worker is not None and self._refresh_worker.isRunning():
            self._refresh_worker.requestInterruption()
            self._refresh_worker.wait(2000)
        self._feed_manager.stop()
        try:
            self._db.close()
        except Exception:
            logger.debug("State database close failed", exc_info=True)

    def poll_feed(self, feed_id: int) -> None:
        self._feed_manager.poll_now(feed_id)
        self.refresh()
