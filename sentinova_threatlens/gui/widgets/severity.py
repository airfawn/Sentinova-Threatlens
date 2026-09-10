from __future__ import annotations

from typing import Any

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from sentinova_threatlens.gui.widgets.presentation import severity_score, severity_tier

_ALPHA = 24


def paint_severity(painter: QPainter, rect: QRectF, record: dict[str, Any]) -> None:
    """Paint a compact severity pill: color-tinted rounded box, bar, score, tier."""
    score = severity_score(record)
    label, hex_color = severity_tier(score)
    color = QColor(hex_color)

    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)

    r = rect.adjusted(0, 4, 0, -4)
    painter.setPen(QPen(color, 1))
    painter.setBrush(QColor(color.red(), color.green(), color.blue(), _ALPHA))
    painter.drawRoundedRect(r, 9, 9)

    inner = r.adjusted(12, 6, -12, -6)
    bar_w = 22
    bar_h = 4
    bar_y = inner.top()

    spacer = 8
    label_w = painter.fontMetrics().horizontalAdvance(label)
    avail = inner.width() - bar_w - spacer * 2 - label_w
    if avail < 0:
        label = label[:3]
        label_w = painter.fontMetrics().horizontalAdvance(label)
        avail = inner.width() - bar_w - spacer * 2 - label_w
    center_x = inner.left() + max(0, avail / 2)
    bar_x = center_x
    score_x = bar_x + bar_w + spacer
    label_x = score_x + 20
    label_x = min(label_x, inner.right() - label_w)

    painter.setBrush(QColor(255, 255, 255, 38))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 2, 2)
    fill_w = int(max(4, bar_w * (score / 100)))
    painter.setBrush(color)
    painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 2, 2)

    score_font = QFont(painter.font())
    score_font.setPointSizeF(max(8, score_font.pointSizeF() - 1))
    score_font.setWeight(QFont.DemiBold)
    painter.setFont(score_font)
    painter.setPen(color)
    painter.drawText(score_x, inner.top() - 6, 22, inner.height(),
                     Qt.AlignLeft | Qt.AlignVCenter, str(score))

    label_font = QFont(painter.font())
    label_font.setPointSizeF(max(7, label_font.pointSizeF() - 1.5))
    label_font.setWeight(QFont.DemiBold)
    painter.setFont(label_font)
    painter.setPen(color)
    painter.drawText(label_x, inner.top() - 6, label_w, inner.height(),
                     Qt.AlignLeft | Qt.AlignVCenter, label)
    painter.restore()


class SeverityPill(QWidget):
    """Standalone severity pill widget (used outside table delegates)."""

    def __init__(self, record: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._record = record
        self.setFixedSize(118, 38)
        self.setCursor(Qt.PointingHandCursor)

    def paintEvent(self, _event: Any) -> None:
        p = QPainter(self)
        p.setFont(self.font())
        paint_severity(p, QRectF(self.rect()), self._record)
        p.end()

    def sizeHint(self) -> Any:
        from PySide6.QtCore import QSize

        return QSize(118, 38)


def tier_color(tier: str) -> QColor:
    mapping = {
        "CRITICAL": "#F0435B",
        "HIGH": "#F08A3C",
        "MEDIUM": "#E8B93C",
        "LOW": "#3FD68B",
    }
    return QColor(mapping.get(tier.upper(), "#8C96A8"))