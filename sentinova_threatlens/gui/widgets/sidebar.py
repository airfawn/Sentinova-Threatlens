from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.widgets.icons import nav_icons

NAV_ITEMS = [
    ("database", "Database"),
    ("dashboard", "Dashboard"),
    ("threats", "Threats"),
    ("sources", "Sources"),
    ("settings", "Settings"),
]


def logo_pixmap(size: int = 42) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)

    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor(theme.ACCENT))
    grad.setColorAt(1.0, QColor("#6FA4FF"))
    p.setPen(Qt.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(0, 0, size, size, size * 0.24, size * 0.24)

    p.setPen(QPen(QColor("#0B0E13"), max(1.5, size * 0.08),
                  Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    cx, cy, r = size / 2, size / 2, size * 0.30
    p.drawEllipse(cx - r, cy - r, 2 * r, 2 * r)
    p.drawLine(cx, cy, cx + r * 0.98, cy - r * 0.60)
    p.end()
    return pm


class Sidebar(QFrame):
    page_requested = Signal(str)

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(248)
        self._icons = nav_icons(QColor(theme.ACCENT), QColor(theme.TEXT_FAINT))
        self._buttons: dict[str, QPushButton] = {}
        self._current: str | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 22, 18, 16)
        root.setSpacing(6)

        brand = QHBoxLayout()
        brand.setSpacing(12)

        logo = QLabel()
        logo.setPixmap(logo_pixmap())
        logo.setFixedSize(42, 42)
        brand.addWidget(logo)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        app_name = QLabel("Sentinova")
        app_name.setObjectName("SidebarTitle")
        titles.addWidget(app_name)
        sub = QLabel("Threatlens · Threat Intel")
        sub.setObjectName("SidebarVersion")
        titles.addWidget(sub)
        brand.addLayout(titles)
        brand.addStretch(1)
        root.addLayout(brand)

        root.addSpacing(12)

        for key, label in NAV_ITEMS:
            btn = QPushButton(label)
            btn.setProperty("class", "NavButton")
            btn.setIconSize(QSize(18, 18))
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _=False, k=key: self.select(k))
            btn.setIcon(self._icons[key]["normal"])
            self._buttons[key] = btn
            root.addWidget(btn)

        root.addStretch(1)

        footer = QFrame()
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(10, 8, 10, 8)
        footer_layout.setSpacing(3)
        status = QLabel("●  Engine idle")
        status.setStyleSheet("color: %s; font-size: 11px; font-weight: 500;" % theme.TEXT_MUTED)
        version = QLabel("CTI Ingestion · v0.1.0")
        version.setObjectName("SidebarVersion")
        footer_layout.addWidget(status)
        footer_layout.addWidget(version)
        root.addWidget(footer)

        self.select("database", emit=False)

    def select(self, key: str, emit: bool = True) -> None:
        if key not in self._buttons:
            return
        self._current = key
        for k, btn in self._buttons.items():
            btn.setChecked(k == key)
            btn.setIcon(self._icons[key]["active"] if k == key else self._icons[k]["normal"])
        if emit:
            self.page_requested.emit(key)