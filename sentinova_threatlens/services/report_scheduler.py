from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from sentinova_threatlens.services.reporting import ReportGenerator

logger = logging.getLogger(__name__)


class ReportScheduler:
    def __init__(self, pending: Callable[[], list[dict[str, Any]]], records: Callable[[], list[dict[str, Any]]], complete: Callable[[int, str], None], interval: int = 30) -> None:
        self._pending, self._records, self._complete = pending, records, complete
        self._interval = max(1, interval)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="threatlens-reports", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            for report in self._pending():
                try:
                    path = f"reports/threatlens-{report['id']}.pdf"
                    artifact = ReportGenerator().generate(path, "Sentinova ThreatLens Report", {"records": len(self._records())}, self._records())
                    self._complete(int(report["id"]), str(artifact))
                except Exception:
                    logger.exception("Scheduled report failed")