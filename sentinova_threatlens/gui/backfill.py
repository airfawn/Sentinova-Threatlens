from __future__ import annotations

"""Background CVSS enrichment so startup never blocks on NVD lookups."""

import logging
from typing import Any

from PySide6.QtCore import QThread, Signal

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.enrichment import CVEEnricher

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 50


class CVSSBackfillWorker(QThread):
    """Walks every stored CVE missing a cached CVSS lookup and resolves it.

    Runs quietly in the background at an adaptively-paced, sequential rate that
    keeps us comfortably under NVD's burst protection (no HTTP 429 spirals).
    Each chunk's results are cached and merged straight into PostgreSQL, so the
    table refreshes with real severity as data arrives.
    """

    progress = Signal(int, int, int)  # done, total, scored so far
    finished = Signal(int, int)       # scored, unfound (definitive no-score)

    def __init__(self, config: AppConfig, db: DatabaseEngine) -> None:
        super().__init__()
        self._config = config
        self._db = db

    def run(self) -> None:
        scored_total = 0
        try:
            pending = self._db.list_pending_cvss()
        except Exception:
            logger.exception("Failed to list pending CVEs")
            self.finished.emit(0, 0)
            return

        total = len(pending)
        if total == 0 or not self._config.sources.cvss_enabled:
            self.finished.emit(0, 0)
            return

        logger.info("Background CVSS backfill starting — %d pending", total)
        enricher = CVEEnricher(self._config.sources)
        try:
            for i in range(0, total, _CHUNK_SIZE):
                if self.isInterruptionRequested():
                    logger.info("CVSS backfill interrupted")
                    break
                chunk = pending[i:i + _CHUNK_SIZE]
                results = enricher.fetch_cvss(chunk)
                if results:
                    self._db.store_cvss_cache([
                        {
                            "cve_id": cid,
                            "cvss_score": info.get("cvss_score"),
                            "cvss_severity": info.get("cvss_severity"),
                            "cvss_vector": info.get("cvss_vector"),
                            "cvss_source": info.get("cvss_source", "NVD"),
                        }
                        for cid, info in results.items()
                    ])
                    with_score = {
                        cid: info for cid, info in results.items()
                        if info.get("cvss_score") is not None
                    }
                    if with_score:
                        self._db.merge_metadata(
                            [(cid, info) for cid, info in with_score.items()])
                        scored_total += len(with_score)
                done = min(i + _CHUNK_SIZE, total)
                self.progress.emit(done, total, scored_total)
        finally:
            enricher.close()

        self.finished.emit(scored_total, total - scored_total)
        logger.info("CVSS backfill complete — %d scored, %d without a score",
                    scored_total, total - scored_total)