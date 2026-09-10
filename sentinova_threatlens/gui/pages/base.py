from __future__ import annotations

from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from sentinova_threatlens.gui import theme


class BasePage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(theme.PAGE_MARGIN, 26, theme.PAGE_MARGIN, 28)
        self._root.setSpacing(20)
        self._fade_effect = QGraphicsOpacityEffect(self)
        self._fade_effect.setOpacity(1.0)
        self._fade: QPropertyAnimation | None = None

    def header(self, title: str, subtitle: str, pill_text: str | None = None) -> None:
        top = QHBoxLayout()
        top.setSpacing(16)

        titles = QVBoxLayout()
        titles.setSpacing(4)
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        titles.addWidget(title_label)
        sub_label = QLabel(subtitle)
        sub_label.setObjectName("PageSubtitle")
        titles.addWidget(sub_label)
        top.addLayout(titles)
        top.addStretch(1)

        if pill_text is not None:
            pill = QLabel(pill_text)
            pill.setObjectName("OnlinePill")
            top.addWidget(pill, 0, Qt.AlignTop)
        self._root.addLayout(top)

    def apply_to(self, widget: QWidget) -> None:
        self._root.addWidget(widget, 1)

    def fade_in(self) -> None:
        self._fade_effect.setOpacity(0.0)
        self.setGraphicsEffect(self._fade_effect)
        self._fade = QPropertyAnimation(self._fade_effect, b"opacity", self)
        self._fade.setDuration(220)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        self._fade.start()