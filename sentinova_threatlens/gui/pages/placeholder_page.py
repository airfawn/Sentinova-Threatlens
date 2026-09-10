from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from sentinova_threatlens.gui.pages.base import BasePage


class PlaceholderPage(BasePage):
    """Builds a clean empty state for navigation entries not yet implemented."""

    def __init__(self, title: str, subtitle: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.header(title, subtitle, None)

        empty = QWidget()
        body = QVBoxLayout(empty)
        body.setContentsMargins(24, 24, 24, 24)
        body.setSpacing(8)
        body.addStretch(1)

        t = QLabel("Nothing here yet")
        t.setObjectName("EmptyTitle")
        t.setAlignment(Qt.AlignCenter)
        body.addWidget(t)

        c = QLabel("This module is coming in a future release.")
        c.setObjectName("EmptyCaption")
        c.setAlignment(Qt.AlignCenter)
        body.addWidget(c)

        body.addStretch(1)
        self._root.addWidget(empty, 1)