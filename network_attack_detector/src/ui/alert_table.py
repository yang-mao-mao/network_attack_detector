"""Real-time alert table with color-coded rows and filtering.

Provides:
- AlertTableModel: QAbstractTableModel holding a list of Alert objects
- AlertTableView: QTableView with color coding by alert level, auto-scroll,
  right-click context menu, and level/category filter controls.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    Qt,
    QSortFilterProxyModel,
    pyqtSignal,
)
from PyQt6.QtGui import QAction, QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QVBoxLayout,
    QWidget,
)

from src.core.models import Alert, AlertLevel

# ── colour constants ──────────────────────────────────────────────────────

LEVEL_COLORS: dict[AlertLevel, QColor] = {
    AlertLevel.CRITICAL: QColor(255, 220, 220),  # light red
    AlertLevel.HIGH: QColor(255, 235, 220),      # light orange
    AlertLevel.MEDIUM: QColor(255, 255, 200),     # light yellow
    AlertLevel.LOW: QColor(220, 235, 255),        # light blue
}

LEVEL_TEXT_COLORS: dict[AlertLevel, QColor] = {
    AlertLevel.CRITICAL: QColor(180, 0, 0),
    AlertLevel.HIGH: QColor(200, 80, 0),
    AlertLevel.MEDIUM: QColor(160, 140, 0),
    AlertLevel.LOW: QColor(0, 80, 160),
}

COLUMNS: list[tuple[str, int]] = [
    ("#", 40),
    ("时间", 160),
    ("等级", 70),
    ("攻击类型", 130),
    ("源 IP", 130),
    ("目的 IP", 130),
    ("协议", 60),
    ("规则名称", 150),
    ("证据", 220),
]

MAX_ALERTS = 5000


class AlertTableModel(QAbstractTableModel):
    """Table model backed by a list of :class:`Alert` objects.

    Emits ``rows_inserted`` (int count) after new rows are appended so that
    the view can auto-scroll.
    """

    rows_inserted = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.alerts: list[Alert] = []

    # ── data access ───────────────────────────────────────────────────

    def add_alert(self, alert: Alert) -> None:
        """Append a single alert, trimming old rows if over the limit."""
        self.add_alerts([alert])

    def add_alerts(self, alerts: list[Alert]) -> None:
        """Append a batch of alerts efficiently."""
        if not alerts:
            return
        row = len(self.alerts)
        self.beginInsertRows(QModelIndex(), row, row + len(alerts) - 1)
        self.alerts.extend(alerts)
        # trim oldest rows when over capacity
        overflow = len(self.alerts) - MAX_ALERTS
        if overflow > 0:
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            del self.alerts[:overflow]
            self.endRemoveRows()
        self.endInsertRows()
        self.rows_inserted.emit(len(alerts))

    def clear(self) -> None:
        """Remove all alerts."""
        if not self.alerts:
            return
        self.beginResetModel()
        self.alerts.clear()
        self.endResetModel()

    def get_alerts(self) -> list[Alert]:
        """Return a copy of the current alert list."""
        return list(self.alerts)

    # ── Qt model interface ────────────────────────────────────────────

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(self.alerts) if not parent.isValid() else 0

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(COLUMNS) if not parent.isValid() else 0

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: C901
        if not index.isValid():
            return None
        alert = self.alerts[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display_data(alert, col)

        if role == Qt.ItemDataRole.BackgroundRole:
            return QBrush(LEVEL_COLORS.get(alert.level, QColor(255, 255, 255)))

        if role == Qt.ItemDataRole.ForegroundRole:
            return QBrush(LEVEL_TEXT_COLORS.get(alert.level, QColor(0, 0, 0)))

        if role == Qt.ItemDataRole.FontRole and alert.level == AlertLevel.CRITICAL:
            font = QFont()
            font.setBold(True)
            return font

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 2, 6):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return alert

        return None

    def _display_data(self, alert: Alert, col: int) -> str:
        """Return display text for a given column index."""
        if col == 0:
            return str(self.alerts.index(alert) + 1)
        if col == 1:
            return datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        if col == 2:
            return alert.level.value
        if col == 3:
            return alert.category.value
        if col == 4:
            return alert.src_ip or "-"
        if col == 5:
            return alert.dst_ip or "-"
        if col == 6:
            return alert.protocol.value
        if col == 7:
            return alert.rule_name
        if col == 8:
            return alert.evidence[:120] + "…" if len(alert.evidence) > 120 else alert.evidence
        return ""

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section][0] if section < len(COLUMNS) else ""
        return None


class _AlertFilterProxy(QSortFilterProxyModel):
    """Proxy that supports filtering by alert level and category."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._level_filter: str | None = None
        self._category_filter: str | None = None

    def set_level_filter(self, level: str | None) -> None:
        self._level_filter = level
        self.invalidateFilter()

    def set_category_filter(self, category: str | None) -> None:
        self._category_filter = category
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if model is None:
            return True
        idx = model.index(source_row, 0)
        alert: Alert = model.data(idx, Qt.ItemDataRole.UserRole)
        if alert is None:
            return True
        if self._level_filter and alert.level.value != self._level_filter:
            return False
        if self._category_filter and alert.category.value != self._category_filter:
            return False
        return True


class AlertTableView(QWidget):
    """Alert table widget with built-in filter bar and context menu."""

    alert_selected = pyqtSignal(Alert)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()

    # ── setup ─────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # --- summary + filter bar ---
        bar = QHBoxLayout()

        self._summary_label = QLabel("告警: 0 条")
        bar.addWidget(self._summary_label)

        bar.addStretch()

        bar.addWidget(QLabel("等级:"))
        self._level_combo = QComboBox()
        self._level_combo.addItem("全部", None)
        for lvl in AlertLevel:
            self._level_combo.addItem(lvl.value, lvl.value)
        self._level_combo.currentIndexChanged.connect(self._on_filter_changed)
        bar.addWidget(self._level_combo)

        bar.addWidget(QLabel("类型:"))
        self._category_combo = QComboBox()
        self._category_combo.addItem("全部", None)
        self._category_combo.setMinimumWidth(120)
        self._category_combo.currentIndexChanged.connect(self._on_filter_changed)
        bar.addWidget(self._category_combo)

        layout.addLayout(bar)

        # --- table ---
        self._table = _AlertTable(self)
        self._model = AlertTableModel(self)
        self._proxy = _AlertFilterProxy(self)
        self._proxy.setSourceModel(self._model)
        self._table.setModel(self._proxy)

        # connect auto-scroll
        self._model.rows_inserted.connect(self._on_rows_inserted)

        layout.addWidget(self._table)

        self._apply_column_widths()

    def _apply_column_widths(self) -> None:
        header = self._table.horizontalHeader()
        for i, (_, width) in enumerate(COLUMNS):
            header.resizeSection(i, width)

    # ── public API ────────────────────────────────────────────────────

    def add_alert(self, alert: Alert) -> None:
        self._model.add_alert(alert)
        self._update_category_combo()

    def add_alerts(self, alerts: list[Alert]) -> None:
        self._model.add_alerts(alerts)
        self._update_category_combo()

    def clear(self) -> None:
        self._model.clear()

    def get_model(self) -> AlertTableModel:
        return self._model

    def get_alerts(self) -> list[Alert]:
        return self._model.get_alerts()

    # ── slots ─────────────────────────────────────────────────────────

    def _on_rows_inserted(self, count: int) -> None:
        self._summary_label.setText(
            f"告警: {self._model.rowCount()} 条"
            f" | Critical: {self._count_by_level(AlertLevel.CRITICAL)}"
            f" | High: {self._count_by_level(AlertLevel.HIGH)}"
            f" | Medium: {self._count_by_level(AlertLevel.MEDIUM)}"
            f" | Low: {self._count_by_level(AlertLevel.LOW)}"
        )

    def _on_filter_changed(self) -> None:
        level = self._level_combo.currentData()
        category = self._category_combo.currentData()
        if isinstance(level, str):
            self._proxy.set_level_filter(level)
        else:
            self._proxy.set_level_filter(None)
        if isinstance(category, str):
            self._proxy.set_category_filter(category)
        else:
            self._proxy.set_category_filter(None)

    def _update_category_combo(self) -> None:
        existing = {self._category_combo.itemText(i) for i in range(1, self._category_combo.count())}
        for alert in self._model.alerts:
            cat = alert.category.value
            if cat not in existing:
                self._category_combo.addItem(cat, cat)
                existing.add(cat)

    def _count_by_level(self, level: AlertLevel) -> int:
        return sum(1 for a in self._model.alerts if a.level == level)


class _AlertTable(QWidget):
    """Thin wrapper around QTableView with context menu and double-click handler.

    Defined as a module-level class so the outer AlertTableView can own the
    model and proxy while this class handles view-specific interaction.
    """

    def __init__(self, alert_view: AlertTableView) -> None:
        super().__init__()
        self._alert_view = alert_view
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        from PyQt6.QtWidgets import QTableView

        self._view = QTableView()
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._view.setAlternatingRowColors(True)
        self._view.setSortingEnabled(True)
        self._view.verticalHeader().setVisible(False)
        self._view.horizontalHeader().setStretchLastSection(True)
        self._view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._view.customContextMenuRequested.connect(self._on_context_menu)
        self._view.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self._view)

    def setModel(self, model: QAbstractTableModel) -> None:  # noqa: N802
        self._view.setModel(model)

    def horizontalHeader(self) -> QHeaderView:  # noqa: N802
        return self._view.horizontalHeader()

    # ── context menu ──────────────────────────────────────────────────

    def _on_context_menu(self, pos) -> None:
        idx = self._view.indexAt(pos)
        if not idx.isValid():
            return
        src_idx = self._view.model().mapToSource(idx) if hasattr(self._view.model(), "mapToSource") else idx
        alert: Alert | None = src_idx.data(Qt.ItemDataRole.UserRole)
        if alert is None:
            return

        menu = QMenu(self)

        detail_action = QAction("查看详情", self)
        detail_action.triggered.connect(lambda: self._alert_view.alert_selected.emit(alert))
        menu.addAction(detail_action)

        copy_action = QAction("复制证据", self)
        copy_action.triggered.connect(lambda: self._copy_evidence(alert))
        menu.addAction(copy_action)

        menu.addSeparator()

        ignore_action = QAction(f"过滤此 IP: {alert.src_ip}", self)
        ignore_action.triggered.connect(lambda: self._filter_by_ip(alert.src_ip))
        menu.addAction(ignore_action)

        menu.exec(self._view.viewport().mapToGlobal(pos))

    def _on_double_click(self, index: QModelIndex) -> None:
        src_idx = self._view.model().mapToSource(index) if hasattr(self._view.model(), "mapToSource") else index
        alert: Alert | None = src_idx.data(Qt.ItemDataRole.UserRole)
        if alert is not None:
            self._alert_view.alert_selected.emit(alert)

    @staticmethod
    def _copy_evidence(alert: Alert) -> None:
        from PyQt6.QtWidgets import QApplication

        QApplication.clipboard().setText(alert.evidence)

    @staticmethod
    def _filter_by_ip(ip: str | None) -> None:
        # Placeholder: signal back to the main window's filter system
        pass
