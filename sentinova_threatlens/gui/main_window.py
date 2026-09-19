from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer  # type: ignore[reportMissingImports]
from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QStackedWidget, QWidget

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.backfill import CVSSBackfillWorker
from sentinova_threatlens.gui.pages.database_page import DatabasePage
from sentinova_threatlens.gui.pages.functional_pages import (
    DashboardPage,
    IncidentsPage,
    SettingsPage,
    SourcesPage,
    ThreatsPage,
)
from sentinova_threatlens.gui.widgets.sidebar import Sidebar
from sentinova_threatlens.gui.state import AppState

_PAGE_META = {
    "database": None,
    "dashboard": ("Dashboard", "Threat posture and ingestion telemetry"),
    "threats": ("Threats", "Deep inspection of individual indicators"),
    "sources": ("Sources", "Threat intelligence source health and status"),
    "settings": ("Settings", "Ingestion and database configuration"),
}


class MainWindow(QMainWindow):
    def __init__(self, config: AppConfig, stats: dict[str, Any] | None = None) -> None:
        super().__init__()
        self._config = config
        self._stats = stats or {}
        self.setWindowTitle("Sentinova Threatlens")
        self.resize(1280, 800)
        self.setMinimumSize(1024, 640)
        self.setObjectName("MainRoot")

        self._db = DatabaseEngine(config)
        self._state = AppState(config, self)

        central = QWidget()
        central.setObjectName("MainRoot")
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(18)

        self._sidebar = Sidebar()
        layout.addWidget(self._sidebar)

        self._stack = QStackedWidget()
        self._stack.setObjectName("StackRoot")
        layout.addWidget(self._stack, 1)

        self._db_page = DatabasePage(config, self._db, self._state.refresh)
        self._state.records_changed.connect(self._db_page.set_records)
        self._pages: dict[str, QWidget] = {
            "database": self._db_page,
            "dashboard": DashboardPage(self._state),
            "threats": ThreatsPage(self._state),
            "incidents": IncidentsPage(self._state),
            "sources": SourcesPage(self._state),
            "settings": SettingsPage(config, self._state),
        }
        self._stack.addWidget(self._db_page)
        for key in ("dashboard", "threats", "incidents", "sources", "settings"):
            self._stack.addWidget(self._pages[key])

        self._sidebar.page_requested.connect(self._on_page)
        self._fade = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade.setDuration(240)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        self._anim_page: QPropertyAnimation | None = None
        self._backfill: CVSSBackfillWorker | None = None
        self._backfill_started = False
        self._state_refreshed = False

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        self._fade.stop()
        self._fade.start()
        if not self._state_refreshed:
            self._state_refreshed = True
            self._state.refresh()
        self._start_backfill()

    # ── Background CVSS enrichment (never blocks the UI) ───────────────
    def _start_backfill(self) -> None:
        if self._backfill_started or not self._config.sources.cvss_enabled:
            return
        self._backfill_started = True
        self._backfill = CVSSBackfillWorker(self._config, self._db)
        self._backfill.progress.connect(self._on_backfill_progress)
        self._backfill.finished.connect(self._on_backfill_finished)
        self._backfill.finished.connect(self._backfill.deleteLater)
        self._backfill.start()

    def _on_backfill_progress(self, done: int, total: int, scored: int) -> None:
        self._db_page.set_cvss_status(
            f"Fetching severity {done:,}/{total:,} · {scored:,} scored",
            visible=True,
        )
        if done % 150 == 0 or done == total:
            self._state.refresh()

    def _on_backfill_finished(self, scored: int, unfound: int) -> None:
        self._db_page.set_cvss_status(
            f"Severity up to date · {scored:,} scored"
            + (f" · {unfound:,} NVD lookup missed" if unfound else ""),
            visible=True,
        )
        self._state.refresh()
        QTimer.singleShot(3000, lambda: self._db_page.set_cvss_status("", False))

    def _on_page(self, key: str) -> None:
        page = self._pages.get(key)
        if page is None:
            return
        prev = self._stack.currentWidget()
        if prev is page:
            return
        if hasattr(prev, "deactivate"):
            prev.deactivate()
        self._stack.setCurrentWidget(page)

    @property
    def database_page(self) -> DatabasePage:
        return self._db_page

    def closeEvent(self, event: Any) -> None:
        if self._backfill is not None:
            self._backfill.requestInterruption()
            self._backfill.wait(2000)
            if self._backfill.isRunning():
                self._backfill.terminate()
                self._backfill.wait(1000)
        try:
            self._db.close()
        except RuntimeError:
            pass
        self._state.close()
        super().closeEvent(event)