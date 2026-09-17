from __future__ import annotations

"""Professional initialization splash that reflects real ingestion work."""

from typing import Any

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.widgets.shadowcard import ShadowCard
from sentinova_threatlens.gui.widgets.sidebar import logo_pixmap
from sentinova_threatlens.pipeline import IngestionPipeline

STEPS = [
    "Database initialized",
    "Importing sources",
    "Checking import rules",
    "Processing indicators",
    "Finalizing database",
]

_STAGE_TO_ITEM = {
    "db_init": 0,
    "import": 1,
    "rules": 2,
    "process": 3,
    "enrich": 3,
    "verify": 4,
    "complete": 4,
}


class _InitWorker(QThread):
    status = Signal(str, str, float, object)
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self._config = config

    def run(self) -> None:
        try:
            pipeline = IngestionPipeline(self._config)
            stats = pipeline.run(self._progress)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        self.done.emit(stats)

    def _progress(self, stage: str, message: str, fraction: float, extra: dict[str, Any] | None) -> None:
        self.status.emit(stage, message, fraction, extra)


class SplashWindow(QWidget):
    opened = Signal(dict)

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self._config = config
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(480, 600)

        self._card = ShadowCard(radius=24, parent=self)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.addWidget(self._card)

        body = QVBoxLayout(self._card)
        body.setContentsMargins(44, 40, 44, 32)
        body.setSpacing(6)

        logo = QLabel()
        logo.setPixmap(logo_pixmap(64))
        logo.setFixedSize(64, 64)
        logo.setAlignment(Qt.AlignCenter)
        body.addWidget(logo, 0, Qt.AlignCenter)

        # Tracked caps are implemented with literal spaces (not QSS
        # letter-spacing, which can mis-size labels and clip glyphs on macOS).
        brand = QLabel("S E N T I N O V A   T H R E A T L E N S")
        brand.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: %s;" % theme.TEXT
        )
        brand.setAlignment(Qt.AlignCenter)
        body.addWidget(brand)

        tagline = QLabel("T H R E A T   I N T E L L I G E N C E")
        tagline.setStyleSheet(
            "font-size: 22px; font-weight: 670; color: %s;" % theme.TEXT
        )
        tagline.setAlignment(Qt.AlignCenter)
        body.addWidget(tagline)

        body.addSpacing(24)

        self._task_label = QLabel("Please wait..")
        self._task_label.setStyleSheet("font-size: 13px; color: %s;" % theme.TEXT)
        body.addWidget(self._task_label, 0, Qt.AlignLeft)

        bar_row = QHBoxLayout()
        bar_row.setSpacing(12)
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(12)
        bar_row.addWidget(self._bar, 1)
        self._percent = QLabel("0%")
        self._percent.setStyleSheet("font-size: 13px; font-weight: 600; color: %s;" % theme.TEXT_MUTED)
        bar_row.addWidget(self._percent)
        body.addLayout(bar_row)

        self._detail_label = QLabel("")
        self._detail_label.setStyleSheet("font-size: 12px; color: %s;" % theme.TEXT_FAINT)
        body.addWidget(self._detail_label)
        body.addSpacing(18)

        self._steps: list[tuple[QLabel, QLabel]] = []
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)
        for row, label_text in enumerate(STEPS):
            icon = QLabel("○")
            icon.setStyleSheet(
                "font-size: 13px; font-weight: 700; color: %s;" % theme.TEXT_FAINT
            )
            icon.setFixedWidth(18)
            label = QLabel(label_text)
            label.setStyleSheet("font-size: 13px; color: %s;" % theme.TEXT_MUTED)
            grid.addWidget(icon, row, 0)
            grid.addWidget(label, row, 1)
            self._steps.append((icon, label))
        body.addLayout(grid)

        body.addSpacing(14)
        footer = QLabel("v0.1.0 ")
        footer.setStyleSheet("font-size: 11px; color: %s;" % theme.TEXT_FAINT)
        footer.setAlignment(Qt.AlignCenter)
        body.addWidget(footer)

        self._worker: _InitWorker | None = None
        self._load_fades()

    def _load_fades(self) -> None:
        self._fade_in = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_in.setDuration(260)
        self._fade_in.setStartValue(0.0)
        self._fade_in.setEndValue(1.0)
        self._fade_in.setEasingCurve(QEasingCurve.OutCubic)

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        self._fade_in.start()

    # ── Execution ───────────────────────────────────────────────
    def start(self) -> None:
        self._worker = _InitWorker(self._config)
        self._worker.status.connect(self._on_status)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_status(self, stage: str, message: str, fraction: float, extra: dict[str, Any] | None) -> None:
        fraction = max(0.0, min(100.0, float(fraction)))
        self._bar.setValue(int(fraction))
        self._percent.setText(f"{int(fraction)}%")
        self._task_label.setText(message)

        if extra and "skipped" in extra and extra.get("skipped"):
            skipped = extra["skipped"]
            reason = next(iter((extra.get("reasons") or {}).keys()), "")
            self._detail_label.setText(f"⚠  {skipped:,} records skipped — {reason}")
        elif extra and "new" in extra:
            self._detail_label.setText(
                f"Importing {extra['new']:,} new indicators — "
                f"{extra['already']:,} already present"
            )
        elif extra and "count" in extra:
            self._detail_label.setText(f"Indicators collected so far: {extra['count']:,}")
        else:
            self._detail_label.setText("")

        item = _STAGE_TO_ITEM.get(stage)
        if item is not None:
            for i, (icon, label) in enumerate(self._steps):
                if i < item:
                    icon.setText("✓")
                    icon.setStyleSheet("font-size: 13px; font-weight: 700; color: %s;" % theme.ONLINE)
                    label.setStyleSheet("font-size: 13px; color: %s;" % theme.TEXT_MUTED)
                elif i == item:
                    icon.setText("→")
                    icon.setStyleSheet("font-size: 13px; font-weight: 700; color: %s;" % theme.ACCENT)
                    label.setStyleSheet(
                        "font-size: 13px; font-weight: 600; color: %s;" % theme.TEXT
                    )

    def _on_done(self, stats: dict) -> None:
        self._bar.setValue(100)
        self._percent.setText("100%")
        for icon, label in self._steps:
            icon.setText("✓")
            icon.setStyleSheet("font-size: 13px; font-weight: 700; color: %s;" % theme.ONLINE)
        self._task_label.setText("Initialization complete")
        if self._worker:
            self._worker.wait()
        self.opened.emit(stats)

    def _on_failed(self, error: str) -> None:
        self._task_label.setText("Initialization failed")
        self._task_label.setStyleSheet("font-size: 13px; color: %s;" % theme.SEVERITY_CRIT)
        self._detail_label.setText(error or "Unknown error")
        if self._worker:
            self._worker.wait()
        self.opened.emit({})