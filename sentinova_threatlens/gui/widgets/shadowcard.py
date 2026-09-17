from __future__ import annotations

from typing import Any

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QFrame

from sentinova_threatlens.gui import theme


def paint_soft_shadow(painter: QPainter, rect: QRectF, radius: float) -> None:
    """Draw a soft drop shadow behind a rounded card using layered alpha passes.

    Self-painted (instead of QGraphicsDropShadowEffect) so translucent macOS
    windows do not render a visible shadow artifact around the transparent area.
    """
    layers = [
        (10, 8.0),
        (18, 5.5),
        (30, 3.5),
        (46, 1.5),
    ]
    for alpha, inset in layers:
        r = rect.adjusted(-inset, 7 - inset, inset, -(7 - inset))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(0, 0, 0, alpha))
        painter.drawRoundedRect(r, radius, radius)


class ShadowCard(QFrame):
    """Rounded dark card with a softly painted shadow; contents added by caller."""

    def __init__(self, radius: int = 24, parent: Any = None) -> None:
        super().__init__(parent)
        self._radius = radius
        self.setAttribute(Qt.WA_StyledBackground, True)

    def paintEvent(self, event: Any) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        paint_soft_shadow(p, rect, self._radius)

        p.setPen(QPen(QColor(theme.BORDER), 1))
        p.setBrush(QColor(theme.CARD))
        p.drawRoundedRect(rect, self._radius, self._radius)
        p.end()

    def sizeHint(self) -> Any:
        from PySide6.QtCore import QSize

        return QSize(400, 300)