from __future__ import annotations

import json
import re
from typing import Any

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sentinova_threatlens.gui import theme


class _Card(QWidget):
    """Rounded, shadowed, draggable card used as the dialog surface."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet("background: %s; border-radius: %dpx; border: 1px solid %s;"
                           % (theme.CARD, theme.MODAL_RADIUS, theme.BORDER))
        self._drag_pos: Any = None

    def mousePressEvent(self, event: Any) -> None:
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: Any) -> None:
        if self._drag_pos is not None and event.buttons() & Qt.LeftButton:
            moving = event.globalPosition().toPoint() - self._drag_pos
            self.window().move(moving)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: Any) -> None:
        self._drag_pos = None
        super().mouseReleaseEvent(event)


class _JSONHighlighter(QSyntaxHighlighter):
    def __init__(self, document: Any) -> None:
        super().__init__(document)
        self._key_re = re.compile(r'"((?:\\"|[^"])*?)"(?=\s*:)')
        self._string_re = re.compile(r'"(?:\\"|[^"])*?"')
        self._number_re = re.compile(r"-?\b\d+\.?\d*(?:[eE][+-]?\d+)?\b")
        self._literal_re = re.compile(r"\b(?:true|false|null)\b")
        self._punct_re = re.compile(r"[{}\[\],:]")

    def highlightBlock(self, text: str) -> None:
        self._apply(self._fmt(theme.ACCENT, bold=True), text, self._key_re)
        self._apply(self._fmt("#6FCF8B"), text, self._string_re, skip_inside_strings=True)
        self._apply(self._fmt("#E8B93C"), text, self._number_re)
        self._apply(self._fmt("#C792EA"), text, self._literal_re)
        self._apply(self._fmt(theme.TEXT_FAINT), text, self._punct_re)

    @staticmethod
    def _fmt(color: str, bold: bool = False) -> QTextCharFormat:
        f = QTextCharFormat()
        f.setForeground(QColor(color))
        f.setFontWeight(QFont.DemiBold if bold else QFont.Normal)
        return f

    def _inside_string(self, text: str, index: int) -> bool:
        in_string = False
        i = 0
        while i < index:
            ch = text[i]
            if in_string:
                if ch == "\\":
                    i += 1
                elif ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            i += 1
        return in_string

    def _apply(self, fmt: QTextCharFormat, text: str, regex: re.Pattern[str], skip_inside_strings: bool = False) -> None:
        for match in regex.finditer(text):
            start, end = match.span()
            if skip_inside_strings and self._inside_string(text, start + 1):
                continue
            self.setFormat(start, end - start, fmt)


class JSONViewDialog(QDialog):
    """Rounded modal displaying a formatted, highlighted JSON payload."""

    def __init__(self, payload: Any, title: str = "Raw JSON", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowModality(Qt.ApplicationModal)
        self.resize(680, 500)

        self._card = _Card(self)
        shadow = QGraphicsDropShadowEffect(self._card)
        shadow.setBlurRadius(48)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 170))
        self._card.setGraphicsEffect(shadow)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.addWidget(self._card)

        card = QVBoxLayout(self._card)
        card.setContentsMargins(24, 20, 24, 24)
        card.setSpacing(14)

        header = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 15px; font-weight: 600; color: %s;" % theme.TEXT)
        header.addWidget(title_label)
        header.addStretch(1)

        self._copy_btn = QPushButton("Copy JSON")
        self._copy_btn.setProperty("class", "Secondary")
        self._copy_btn.clicked.connect(self._copy)
        header.addWidget(self._copy_btn)

        close_btn = QPushButton("Close")
        close_btn.setProperty("class", "Primary")
        close_btn.clicked.connect(self.accept)
        header.addWidget(close_btn)
        card.addLayout(header)

        self._editor = QPlainTextEdit()
        self._editor.setReadOnly(True)
        self._editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._editor.document().setPlainText(json.dumps(payload, indent=2, default=str))
        self._highlighter = _JSONHighlighter(self._editor.document())
        card.addWidget(self._editor, 1)

        self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_anim.setDuration(150)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.setEasingCurve(QEasingCurve.OutCubic)

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        self._fade_anim.stop()
        self._fade_anim.start()

    def _copy(self) -> None:
        QApplication.clipboard().setText(self._editor.document().toPlainText())
        self._copy_btn.setText("Copied ✓")

    def keyPressEvent(self, event: Any) -> None:
        if event.key() == Qt.Key_Escape:
            self.accept()
            return
        super().keyPressEvent(event)