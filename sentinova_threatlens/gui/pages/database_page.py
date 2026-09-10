from __future__ import annotations

"""Database page: live threat-intelligence records from PostgreSQL."""

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.pages.base import BasePage
from sentinova_threatlens.gui.widgets.json_viewer import JSONViewDialog
from sentinova_threatlens.gui.widgets.presentation import (
    display_c2,
    display_name,
    severity_score,
    severity_tier,
    source_label,
)
from sentinova_threatlens.gui.widgets.severity import paint_severity

SORT_ROLE = Qt.UserRole + 1
_HEADERS = [
    ("name", "Name"),
    ("c2", "Website / C2"),
    ("severity", "Severity"),
    ("source", "Source"),
    ("raw", "Raw JSON"),
]


def _records_of(model: QSortFilterProxyModel) -> list[dict[str, Any]]:
    src = model.sourceModel()
    return src.records if isinstance(src, _TableModel) else []


class _TableModel(QAbstractTableModel):
    def __init__(self, records: list[dict[str, Any]], parent: Any = None) -> None:
        super().__init__(parent)
        self._records = records

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._records

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(_HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole and section < len(_HEADERS):
            return _HEADERS[section][1]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._records):
            return None
        rec = self._records[index.row()]
        col = _HEADERS[index.column()][0]

        if role == Qt.DisplayRole or role == Qt.ToolTipRole:
            if col == "name":
                return display_name(rec)
            if col == "c2":
                return display_c2(rec)
            if col == "severity":
                score = severity_score(rec)
                return f"{score} · {severity_tier(score)[0]}"
            if col == "source":
                return source_label(rec)
            if col == "raw":
                return "View JSON →"

        if role == SORT_ROLE:
            return self._sort_value(rec, col)

        if role == Qt.ForegroundRole:
            if col in ("c2", "source"):
                return QColor(theme.TEXT_MUTED)
            if col == "raw":
                return QColor(theme.ACCENT)
        if role == Qt.TextAlignmentRole and col == "severity":
            return Qt.AlignCenter
        return None

    @staticmethod
    def _sort_value(rec: dict[str, Any], col: str) -> Any:
        if col == "severity":
            return severity_score(rec)
        if col == "name":
            return str(display_name(rec)).lower()
        if col == "c2":
            return str(display_c2(rec)).lower()
        if col == "source":
            return str(source_label(rec)).lower()
        return str(rec.get("ioc_value", "")).lower()


class _FilterProxy(QSortFilterProxyModel):
    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._search = ""
        self.setDynamicSortFilter(True)
        self.setSortRole(SORT_ROLE)

    def set_search(self, text: str) -> None:
        self._search = text.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        if not self._search:
            return True
        model = self.sourceModel()
        for col in range(model.columnCount()):
            idx = model.index(row, col, parent)
            value = model.data(idx, SORT_ROLE)
            if value is not None and self._search in str(value).lower():
                return True
        return False

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        l_val = self.sourceModel().data(left, SORT_ROLE)
        r_val = self.sourceModel().data(right, SORT_ROLE)
        if isinstance(l_val, (int, float)) and isinstance(r_val, (int, float)):
            return l_val < r_val
        return str(l_val or "").lower() < str(r_val or "").lower()


class _SeverityDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option: Any, index: QModelIndex) -> None:
        records = _records_of(index.model())
        if index.isValid() and index.row() < len(records) and index.column() == 2:
            painter.save()
            if option.state & QStyle.State_Selected:
                painter.fillRect(option.rect, QColor(79, 140, 255, 40))
            paint_severity(painter, option.rect, records[index.row()])
            painter.restore()
            return
        super().paint(painter, option, index)


class _LinkDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option: Any, index: QModelIndex) -> None:
        if index.isValid() and index.column() == 4:
            painter.save()
            painter.setPen(QPen(QColor(theme.ACCENT)))
            f = QFont(painter.font())
            f.setPointSizeF(12)
            f.setWeight(QFont.DemiBold)
            painter.setFont(f)
            painter.drawText(option.rect, Qt.AlignCenter, "View JSON →")
            painter.restore()
            return
        super().paint(painter, option, index)


class DatabasePage(BasePage):
    def __init__(self, config: AppConfig, db: DatabaseEngine, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self._db = db
        self._records: list[dict[str, Any]] = []
        self._proxy = _FilterProxy(self)
        self._model = _TableModel([], self)
        self._proxy.setSourceModel(self._model)
        self._dialog: JSONViewDialog | None = None

        self.header(
            "Threat Intelligence Database",
            "Imported indicators and threat intelligence records",
            "●  Database Online",
        )
        self._build_toolbar()
        self._build_table()

        self.reload()

    def _build_toolbar(self) -> None:
        from PySide6.QtWidgets import QHBoxLayout

        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search name, IOC, source…")
        self._search.setFixedWidth(320)
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._proxy.set_search)
        toolbar.addWidget(self._search)

        self._count_label = QLabel("0 records")
        self._count_label.setObjectName("CardCaption")
        toolbar.addWidget(self._count_label)
        toolbar.addStretch(1)

        refresh = QPushButton("Refresh")
        refresh.setProperty("class", "Secondary")
        refresh.clicked.connect(self.reload)
        toolbar.addWidget(refresh)
        self._root.addLayout(toolbar)

    def _build_table(self) -> None:
        card = QWidget()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(0)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setShowGrid(False)
        self._table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self._table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(50)
        self._table.setItemDelegateForColumn(2, _SeverityDelegate(self._table))
        self._table.setItemDelegateForColumn(4, _LinkDelegate(self._table))

        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.setColumnWidth(2, 150)
        self._table.setColumnWidth(4, 110)

        self._table.clicked.connect(self._on_row_clicked)

        card_layout.addWidget(self._table)
        self._root.addWidget(card, 1)

    def reload(self) -> None:
        try:
            self._db.connect()
            records = self._db.fetch_all(limit=50000)
        except Exception:
            import logging

            logging.getLogger("gui.database_page").exception("Failed to load records")
            records = []
        self._records = records or []
        self._model = _TableModel(self._records, self)
        self._proxy.setSourceModel(self._model)
        self._count_label.setText(f"{len(self._records):,} records")
        self._table.sortByColumn(2, Qt.DescendingOrder)

    def _on_row_clicked(self, index: QModelIndex) -> None:
        if index.column() != 4:
            return
        src_row = self._proxy.mapToSource(index).row()
        if 0 <= src_row < len(self._records):
            payload = self._records[src_row].get("raw_data")
            if payload is not None:
                self._dialog = JSONViewDialog(
                    payload,
                    title="Raw JSON — original source payload",
                    parent=self,
                )
                self._dialog.exec()