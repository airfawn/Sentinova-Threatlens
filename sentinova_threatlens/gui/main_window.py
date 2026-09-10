from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QStackedWidget, QWidget

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.pages.database_page import DatabasePage
from sentinova_threatlens.gui.pages.placeholder_page import PlaceholderPage
from sentinova_threatlens.gui.widgets.sidebar import Sidebar

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

        self._db_page = DatabasePage(config, self._db)
        self._pages: dict[str, QWidget] = {
            "database": self._db_page,
        }
        self._stack.addWidget(self._db_page)

        for key, meta in _PAGE_META.items():
            if key == "database" or not meta:
                continue
            title, subtitle = meta
            page = PlaceholderPage(title, subtitle)
            self._pages[key] = page
            self._stack.addWidget(page)

        self._sidebar.page_requested.connect(self._on_page)
        self._fade = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade.setDuration(240)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        self._anim_page: QPropertyAnimation | None = None

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        self._fade.stop()
        self._fade.start()

    def _on_page(self, key: str) -> None:
        page = self._pages.get(key)
        if page is None:
            return
        prev = self._stack.currentWidget()
        if prev is page:
            return
        self._stack.setCurrentWidget(page)
        if key == "database":
            self._db_page.reload()
        if hasattr(page, "fade_in"):
            page.fade_in()

    @property
    def database_page(self) -> DatabasePage:
        return self._db_page

    def closeEvent(self, event: Any) -> None:
        try:
            self._db.close()
        except RuntimeError:
            pass
        super().closeEvent(event)