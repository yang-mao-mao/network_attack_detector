"""Real-time traffic table displaying captured packet summaries.

Provides:
- TrafficTableModel: QAbstractTableModel backed by a list of PacketInfo objects
- TrafficTableView: QTableView wrapper with auto-scroll, context menu,
  protocol filter, and a summary label bar.
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
from PyQt6.QtGui import QAction, QBrush, QColor
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

from src.core.models import PacketInfo, Protocol

# ── colour constants ──────────────────────────────────────────────────────

HTTP_COLOR = QColor(230, 240, 255)  # light blue background for HTTP packets

COLUMNS: list[tuple[str, int]] = [
    ("#", 45),
    ("时间", 150),
    ("源 IP", 130),
    ("源端口", 70),
    ("目的 IP", 130),
    ("目的端口", 70),
    ("协议", 60),
    ("长度", 65),
    ("摘要", 220),
]

MAX_PACKETS = 10000


class TrafficTableModel(QAbstractTableModel):
    """Table model backed by a list of :class:`PacketInfo` objects.

    Emits ``rows_inserted`` (int count) so the view can auto-scroll.
    """

    rows_inserted = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.packets: list[PacketInfo] = []

    # ── data access ───────────────────────────────────────────────────

    def add_packet(self, packet: PacketInfo) -> None:
        """Append a single packet, evicting old rows when over capacity."""
        row = len(self.packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self.packets.append(packet)
        # trim oldest rows
        overflow = len(self.packets) - MAX_PACKETS
        if overflow > 0:
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            del self.packets[:overflow]
            self.endRemoveRows()
        self.endInsertRows()
        self.rows_inserted.emit(1)

    def clear(self) -> None:
        """Remove all packets."""
        if not self.packets:
            return
        self.beginResetModel()
        self.packets.clear()
        self.endResetModel()

    def get_packets(self) -> list[PacketInfo]:
        """Return a copy of the current packet list."""
        return list(self.packets)

    # ── Qt model interface ────────────────────────────────────────────

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(self.packets) if not parent.isValid() else 0

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return len(COLUMNS) if not parent.isValid() else 0

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        packet = self.packets[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display_data(packet, col)

        if role == Qt.ItemDataRole.BackgroundRole:
            if packet.protocol == Protocol.HTTP:
                return QBrush(HTTP_COLOR)
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 3, 5, 6, 7):
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole:
            return packet

        return None

    def _display_data(self, packet: PacketInfo, col: int) -> str:
        """Return display text for a given column index."""
        if col == 0:
            return str(self.packets.index(packet) + 1)
        if col == 1:
            return datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3]
        if col == 2:
            return packet.src_ip or "-"
        if col == 3:
            return str(packet.src_port) if packet.src_port is not None else "-"
        if col == 4:
            return packet.dst_ip or "-"
        if col == 5:
            return str(packet.dst_port) if packet.dst_port is not None else "-"
        if col == 6:
            return packet.protocol.value
        if col == 7:
            return str(packet.length)
        if col == 8:
            return packet.raw_summary[:150] + "…" if len(packet.raw_summary) > 150 else packet.raw_summary
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


class _ProtocolFilterProxy(QSortFilterProxyModel):
    """Proxy that filters traffic by protocol."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._protocol_filter: str | None = None

    def set_protocol_filter(self, protocol: str | None) -> None:
        self._protocol_filter = protocol
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        if self._protocol_filter is None:
            return True
        model = self.sourceModel()
        if model is None:
            return True
        idx = model.index(source_row, 6)  # protocol column
        return model.data(idx, Qt.ItemDataRole.DisplayRole) == self._protocol_filter


class TrafficTableView(QWidget):
    """Traffic table widget with protocol filter bar and context menu."""

    packet_selected = pyqtSignal(PacketInfo)

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

        self._summary_label = QLabel("流量: 0 条")
        bar.addWidget(self._summary_label)

        bar.addStretch()

        bar.addWidget(QLabel("协议:"))
        self._protocol_combo = QComboBox()
        self._protocol_combo.addItem("全部", None)
        for proto in Protocol:
            self._protocol_combo.addItem(proto.value, proto.value)
        self._protocol_combo.currentIndexChanged.connect(self._on_filter_changed)
        bar.addWidget(self._protocol_combo)

        layout.addLayout(bar)

        # --- table ---
        self._table = _TrafficTable(self)
        self._model = TrafficTableModel(self)
        self._proxy = _ProtocolFilterProxy(self)
        self._proxy.setSourceModel(self._model)
        self._table.setModel(self._proxy)

        self._model.rows_inserted.connect(self._on_rows_inserted)

        layout.addWidget(self._table)

        self._apply_column_widths()

    def _apply_column_widths(self) -> None:
        header = self._table.horizontalHeader()
        for i, (_, width) in enumerate(COLUMNS):
            header.resizeSection(i, width)

    # ── public API ────────────────────────────────────────────────────

    def add_packet(self, packet: PacketInfo) -> None:
        """Add a single packet to the table."""
        self._model.add_packet(packet)

    def clear(self) -> None:
        """Clear all rows."""
        self._model.clear()

    def get_model(self) -> TrafficTableModel:
        """Return the backing data model."""
        return self._model

    def get_packets(self) -> list[PacketInfo]:
        """Return a copy of all packets currently in the model."""
        return self._model.get_packets()

    # ── slots ─────────────────────────────────────────────────────────

    def _on_rows_inserted(self, _count: int) -> None:
        self._summary_label.setText(f"流量: {self._model.rowCount()} 条")

    def _on_filter_changed(self) -> None:
        proto = self._protocol_combo.currentData()
        self._proxy.set_protocol_filter(proto if isinstance(proto, str) else None)


class _TrafficTable(QWidget):
    """Thin wrapper around QTableView with context menu and interaction."""

    def __init__(self, traffic_view: TrafficTableView) -> None:
        super().__init__()
        self._traffic_view = traffic_view
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
        src_idx = (
            self._view.model().mapToSource(idx)
            if hasattr(self._view.model(), "mapToSource")
            else idx
        )
        packet: PacketInfo | None = src_idx.data(Qt.ItemDataRole.UserRole)
        if packet is None:
            return

        menu = QMenu(self)

        detail_action = QAction("查看详情", self)
        detail_action.triggered.connect(lambda: self._traffic_view.packet_selected.emit(packet))
        menu.addAction(detail_action)

        menu.addSeparator()

        if packet.src_ip:
            copy_src = QAction(f"复制源 IP: {packet.src_ip}", self)
            copy_src.triggered.connect(lambda: self._copy_text(packet.src_ip or ""))
            menu.addAction(copy_src)

        if packet.dst_ip:
            copy_dst = QAction(f"复制目的 IP: {packet.dst_ip}", self)
            copy_dst.triggered.connect(lambda: self._copy_text(packet.dst_ip or ""))
            menu.addAction(copy_dst)

        menu.exec(self._view.viewport().mapToGlobal(pos))

    def _on_double_click(self, index: QModelIndex) -> None:
        src_idx = (
            self._view.model().mapToSource(index)
            if hasattr(self._view.model(), "mapToSource")
            else index
        )
        packet: PacketInfo | None = src_idx.data(Qt.ItemDataRole.UserRole)
        if packet is not None:
            self._traffic_view.packet_selected.emit(packet)

    @staticmethod
    def _copy_text(text: str) -> None:
        from PyQt6.QtWidgets import QApplication

        QApplication.clipboard().setText(text)
