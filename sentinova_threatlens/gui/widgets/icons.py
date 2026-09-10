from __future__ import annotations

from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QPixmap

SIZE = 18

_ICONS = {
    "database",
    "dashboard",
    "threats",
    "sources",
    "settings",
}


def draw_icon(painter: QPainter, name: str, color: QColor) -> None:
    pen = QPen(color)
    pen.setWidthF(1.6)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)

    w, h = SIZE, SIZE
    if name == "database":
        r_top = QRectF(2.5, 4.0, w - 5.0, 4.5)
        painter.drawEllipse(r_top)
        painter.drawArc(r_top.translated(0, 5.3), 0 * 16, 180 * 16)
        painter.drawArc(r_top.translated(0, 5.3), 180 * 16, 180 * 16)

    elif name == "dashboard":
        painter.setBrush(QColor(0, 0, 0, 0))
        painter.drawRoundedRect(QRectF(2.5, 2.5, 6.0, 6.0), 1.5, 1.5)
        painter.drawRoundedRect(QRectF(9.5, 2.5, 6.0, 6.0), 1.5, 1.5)
        painter.drawRoundedRect(QRectF(2.5, 9.5, 6.0, 6.0), 1.5, 1.5)
        painter.drawRoundedRect(QRectF(9.5, 9.5, 6.0, 6.0), 1.5, 1.5)

    elif name == "threats":
        path = QPainterPath()
        path.moveTo(9.0, 2.2)
        path.lineTo(14.5, 4.3)
        path.lineTo(14.5, 9.2)
        path.cubicTo(14.5, 12.4, 12.3, 14.6, 9.0, 15.9)
        path.cubicTo(5.7, 14.6, 3.5, 12.4, 3.5, 9.2)
        path.lineTo(3.5, 4.3)
        path.closeSubpath()
        painter.drawPath(path)

    elif name == "sources":
        painter.setBrush(QColor(0, 0, 0, 0))
        painter.drawRoundedRect(QRectF(3.2, 8.2, 11.6, 6.0), 3.0, 3.0)
        painter.drawEllipse(QPointF(6.0, 6.4), 2.1, 2.1)
        painter.drawEllipse(QPointF(11.2, 5.6), 2.4, 2.4)

    elif name == "settings":
        painter.setBrush(QColor(0, 0, 0, 0))
        painter.drawEllipse(QPointF(9.0, 9.0), 3.3, 3.3)
        for angle in range(0, 360, 45):
            import math

            rad = math.radians(angle)
            x1 = 9.0 + math.cos(rad) * 5.2
            y1 = 9.0 + math.sin(rad) * 5.2
            x2 = 9.0 + math.cos(rad) * 6.5
            y2 = 9.0 + math.sin(rad) * 6.5
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))


def render(name: str, color: QColor) -> QPixmap:
    pm = QPixmap(SIZE, SIZE)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    draw_icon(p, name, color)
    p.end()
    return pm


def nav_icons(active: QColor, normal: QColor) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "normal": render(name, normal),
            "active": render(name, active),
        }
        for name in sorted(_ICONS)
    }