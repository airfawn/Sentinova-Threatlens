from __future__ import annotations

import csv
import json
from collections import Counter
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.pages.base import BasePage
from sentinova_threatlens.gui.state import AppState
from sentinova_threatlens.gui.widgets.presentation import severity_score
from sentinova_threatlens.validation import CANONICAL_IOC_TYPES


def _card(title: str, value: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("SubCard")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    label = QLabel(title)
    label.setObjectName("CardCaption")
    amount = QLabel(value)
    amount.setObjectName("StatValue")
    layout.addWidget(label)
    layout.addWidget(amount)
    return frame


def _table_card(table: QTableWidget) -> QFrame:
    card = QFrame()
    card.setObjectName("Card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    table.setObjectName("DataTable")
    layout.addWidget(table)
    return card


class DashboardPage(BasePage):
    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._state = state
        self.header("Executive Overview", "Threat posture and ingestion telemetry", "●  Live")
        self._metrics = QHBoxLayout()
        self._metric_values: list[QLabel] = []
        for title in ("Total IOCs", "High priority", "Sources", "Average score"):
            frame = QFrame()
            frame.setObjectName("SubCard")
            body = QVBoxLayout(frame)
            body.setContentsMargins(16, 14, 16, 14)
            caption = QLabel(title)
            caption.setObjectName("CardCaption")
            value = QLabel("0")
            value.setObjectName("StatValue")
            body.addWidget(caption)
            body.addWidget(value)
            self._metric_values.append(value)
            self._metrics.addWidget(frame, 1)
        self._root.addLayout(self._metrics)

        breakdown_card = QFrame()
        breakdown_card.setObjectName("SubCard")
        breakdown_layout = QVBoxLayout(breakdown_card)
        breakdown_layout.setContentsMargins(18, 16, 18, 16)
        title = QLabel("Threat category breakdown")
        title.setObjectName("CardTitle")
        breakdown_layout.addWidget(title)
        self._breakdown = QLabel("Waiting for ingestion data.")
        self._breakdown.setObjectName("CardCaption")
        self._breakdown.setWordWrap(True)
        breakdown_layout.addWidget(self._breakdown)
        self._root.addWidget(breakdown_card)
        self._root.addStretch(1)
        state.records_changed.connect(self._render)
        state.sources_changed.connect(lambda _items: self._render(state.records))
        self._render([])

    def _render(self, records: list[dict[str, Any]]) -> None:
        scores = [severity_score(record) for record in records]
        types = Counter((record.get("normalized_data", {}) or {}).get("threat_type", "unknown") for record in records)
        values = (len(records), sum(score >= 75 for score in scores), len(self._state.sources), round(sum(scores) / len(scores)) if scores else 0)
        for label, value in zip(self._metric_values, values):
            label.setText(f"{value:,}")
        self._breakdown.setText("Threat categories: " + (" · ".join(f"{key}: {value:,}" for key, value in types.most_common()) or "No records"))


class ThreatsPage(BasePage):
    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._state = state
        self._records: list[dict[str, Any]] = []
        self.header("Threats", "Search, triage, enrich, and export indicators", "●  Analyst")
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        self._search = QLineEdit()
        self._search.setObjectName("ThreatSearch")
        self._search.setPlaceholderText("Search indicator or source...")
        self._search.textChanged.connect(self._render)
        toolbar.addWidget(self._search, 1)
        selector = QVBoxLayout()
        selector.setSpacing(4)
        selector_label = QLabel("IOC type / field")
        selector_label.setObjectName("ControlLabel")
        selector.addWidget(selector_label)
        self._ioc_type = QComboBox()
        self._ioc_type.setObjectName("IocTypeSelector")
        self._ioc_type.setMinimumWidth(190)
        self._ioc_type.setToolTip("Filter the IOC table by the normalized indicator type.")
        self._ioc_type.addItem("All IOC types", "")
        for ioc_type in sorted(CANONICAL_IOC_TYPES):
            self._ioc_type.addItem(ioc_type.replace("HASH_", "Hash "), ioc_type)
        self._ioc_type.currentIndexChanged.connect(self._render)
        selector.addWidget(self._ioc_type)
        toolbar.addLayout(selector)
        export_csv = QPushButton("Export CSV")
        export_csv.setProperty("class", "Secondary")
        export_csv.clicked.connect(self._export_csv)
        toolbar.addWidget(export_csv)
        export_stix = QPushButton("Export STIX")
        export_stix.setProperty("class", "Primary")
        export_stix.clicked.connect(self._export_stix)
        toolbar.addWidget(export_stix)
        self._root.addLayout(toolbar)

        content = QHBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(16)
        self._table = QTableWidget(0, 4)
        self._table.setObjectName("DataTable")
        self._table.setHorizontalHeaderLabels(["Indicator", "Type", "Score", "Source"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.cellClicked.connect(self._show_detail)
        content.addWidget(self._table, 3)

        self._drawer = QFrame()
        self._drawer.setObjectName("SubCard")
        drawer_layout = QVBoxLayout(self._drawer)
        drawer_layout.setContentsMargins(16, 14, 16, 14)
        drawer_layout.addWidget(QLabel("IOC detail"))
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        drawer_layout.addWidget(self._detail, 1)
        self._drawer.setMinimumWidth(280)
        content.addWidget(self._drawer, 1)
        content_frame = QFrame()
        content_frame.setObjectName("Card")
        content_frame.setLayout(content)
        self._root.addWidget(content_frame, 1)
        state.records_changed.connect(self._set_records)
        self._set_records([])

    def _set_records(self, records: list[dict[str, Any]]) -> None:
        self._records = records
        self._render()

    def _render(self) -> None:
        query = self._search.text().lower().strip()
        selected_type = str(self._ioc_type.currentData() or "")
        visible = []
        for record in self._records:
            normalized = record.get("normalized_data", {}) or {}
            if selected_type and normalized.get("ioc_type") != selected_type:
                continue
            if query and query not in json.dumps(record, default=str).lower():
                continue
            visible.append(record)
        self._table.setRowCount(len(visible))
        for row, record in enumerate(visible):
            normalized = record.get("normalized_data", {}) or {}
            values = [record.get("ioc_value", ""), normalized.get("ioc_type", ""), str(severity_score(record)), record.get("source_name", "")]
            for column, value in enumerate(values):
                self._table.setItem(row, column, QTableWidgetItem(str(value)))
        self._table.resizeColumnsToContents()
        self._table.horizontalHeader().setStretchLastSection(True)
        self._detail.clear()

    def deactivate(self) -> None:
        self._ioc_type.hidePopup()

    def _show_detail(self, row: int, _column: int) -> None:
        query = self._search.text().lower().strip()
        selected_type = str(self._ioc_type.currentData() or "")
        visible = [
            record for record in self._records
            if (not selected_type or (record.get("normalized_data", {}) or {}).get("ioc_type") == selected_type)
            and (not query or query in json.dumps(record, default=str).lower())
        ]
        if row < len(visible):
            record = visible[row]
            self._detail.setPlainText(json.dumps(record, indent=2, default=str))

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "iocs.csv", "CSV files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["ioc_value", "ioc_type", "source_name", "severity_score"])
            writer.writeheader()
            for record in self._records:
                normalized = record.get("normalized_data", {}) or {}
                writer.writerow({"ioc_value": record.get("ioc_value"), "ioc_type": normalized.get("ioc_type"), "source_name": record.get("source_name"), "severity_score": severity_score(record)})

    def _export_stix(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export STIX bundle", "iocs.stix.json", "JSON files (*.json)")
        if not path:
            return
        objects = []
        for record in self._records:
            normalized = record.get("normalized_data", {}) or {}
            objects.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{abs(hash(record.get('ioc_value', ''))):032x}", "pattern_type": "stix", "pattern": f"[x-threatlens:value = '{record.get('ioc_value', '')}']", "labels": normalized.get("tags", []), "confidence": normalized.get("confidence_score", 0), "created": str(record.get("first_seen", "")), "modified": str(record.get("last_seen", ""))})
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"type": "bundle", "id": "bundle--threatlens-export", "objects": objects}, handle, indent=2, default=str)


class SourcesPage(BasePage):
    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._state = state
        self.header("Sources", "Feed health and normalized record coverage", "●  Monitoring")
        actions = QHBoxLayout()
        add = QPushButton("Add feed")
        add.setProperty("class", "Primary")
        add.clicked.connect(self._add_feed)
        actions.addWidget(add)
        poll = QPushButton("Poll selected")
        poll.setProperty("class", "Secondary")
        poll.clicked.connect(self._poll_selected)
        actions.addWidget(poll)
        actions.addStretch(1)
        self._root.addLayout(actions)
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Feed", "Enabled", "Interval", "Status", "Last poll"])
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._root.addWidget(_table_card(self._table), 1)
        self._feeds: list[dict[str, Any]] = []
        state.feeds_changed.connect(self._render)
        self._render([])

    def _render(self, feeds: list[dict[str, Any]]) -> None:
        self._feeds = feeds
        self._table.setRowCount(len(feeds))
        for row, feed in enumerate(feeds):
            for column, key in enumerate(("name", "enabled", "poll_interval_seconds", "status", "last_poll")):
                self._table.setItem(row, column, QTableWidgetItem(str(feed.get(key, "-"))))
        self._table.resizeColumnsToContents()

    def _poll_selected(self) -> None:
        row = self._table.currentRow()
        if 0 <= row < len(self._feeds):
            try:
                self._state.poll_feed(int(self._feeds[row]["id"]))
            except Exception:
                self._state.error.emit("Feed poll failed")

    def _add_feed(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Add feed")
        form = QFormLayout(dialog)
        name = QLineEdit()
        endpoint = QLineEdit()
        interval = QLineEdit("3600")
        form.addRow("Name", name)
        form.addRow("Endpoint", endpoint)
        form.addRow("Interval (s)", interval)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.Accepted and name.text().strip() and endpoint.text().strip():
            try:
                self._state._repo.save_feed({"name": name.text().strip(), "endpoint": endpoint.text().strip(), "poll_interval_seconds": int(interval.text() or "3600")}, "desktop")
                self._state.refresh()
            except Exception:
                self._state.error.emit("Feed save failed")


class IncidentsPage(BasePage):
    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._state = state
        self._incidents: list[dict[str, Any]] = []
        self.header("Incidents", "Investigate, assign, and transition correlated alerts", "●  Response")
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Title", "Status", "Assignee", "Score"])
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._root.addWidget(_table_card(self._table), 1)
        actions = QHBoxLayout()
        self._status = QComboBox()
        self._status.addItems(["acknowledged", "in-progress", "resolved", "closed"])
        actions.addWidget(self._status)
        transition = QPushButton("Transition selected")
        transition.setProperty("class", "Primary")
        transition.clicked.connect(self._transition)
        actions.addWidget(transition)
        actions.addStretch(1)
        self._root.addLayout(actions)
        state.incidents_changed.connect(self._render)
        self._render([])

    def _render(self, incidents: list[dict[str, Any]]) -> None:
        self._incidents = incidents
        self._table.setRowCount(len(incidents))
        for row, incident in enumerate(incidents):
            for column, key in enumerate(("title", "status", "assignee", "severity_score")):
                self._table.setItem(row, column, QTableWidgetItem(str(incident.get(key, "-"))))
        self._table.resizeColumnsToContents()

    def _transition(self) -> None:
        row = self._table.currentRow()
        if not (0 <= row < len(self._incidents)):
            return
        current = str(self._incidents[row].get("status", "new"))
        target = self._status.currentText()
        try:
            from sentinova_threatlens.compliance import validate_transition
            from sentinova_threatlens.db.compliance import ComplianceRepository
            validate_transition(current, target)
            repo = ComplianceRepository(self._state._db)
            repo.transition(int(self._incidents[row]["id"]), target, "desktop", None, "Desktop lifecycle transition")
            self._state.refresh()
        except Exception:
            self._state.error.emit("Invalid incident transition")


class SettingsPage(BasePage):
    def __init__(self, config: AppConfig, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.header("Settings", "Local service and ingestion configuration", "●  Ready")
        form = QFormLayout()
        for label, value in (("Database", f"{config.db.host}:{config.db.port}/{config.db.name}"), ("API", f"{config.api.host}:{config.api.port}"), ("Redis", "Enabled" if config.redis.enabled else "Disabled"), ("Role", config.api.role)):
            field = QLineEdit(value)
            field.setReadOnly(True)
            form.addRow(label, field)
        body = QFrame()
        body.setObjectName("SubCard")
        body.setContentsMargins(12, 12, 12, 12)
        body.setLayout(form)
        self._root.addWidget(body, 0)
        refresh = QPushButton("Refresh state")
        refresh.setProperty("class", "Secondary")
        refresh.clicked.connect(state.refresh)
        self._root.addWidget(refresh, 0, Qt.AlignLeft)
        self._root.addStretch(1)
