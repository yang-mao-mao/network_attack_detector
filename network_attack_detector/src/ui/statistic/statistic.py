#!/usr/bin/env python3
"""
Statistics — aggregated attack detection and packet capture overview.

Access restriction (per task1.md):
  - Read+Write: only files in this directory (statistic/).
  - Read-only:   files elsewhere — writing outside is forbidden.

Layout
------
  +-----------------------------------------------------------+
  |  QSplitter (horizontal)                                    |
  |  +--------------------------+----------------------------+ |
  |  | AttackClockWidget        | QSplitter (vertical)       | |
  |  | (square, left panel)     | +------------------------+ | |
  |  |  24-hour circle clock    | | AttackDetailPanel      | | |
  |  |  HH:MM center time       | | (right-upper)          | | |
  |  |  Attack markers (!)      | +------------------------+ | |
  |  +--------------------------+ | IpRankingPanel         | | |
  |                               | (right-lower)          | | |
  |                               +------------------------+ | |
  +-----------------------------------------------------------+

Dependencies: PyQt6 only (per task restriction).
"""

from __future__ import annotations

import math
import random
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QRectF, QPointF
from PyQt6.QtGui import (
    QAction,
    QColor,
    QFont,
    QPainter,
    QPen,
)
from PyQt6.QtWidgets import (
    QApplication,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# =============================================================================
# Path helpers — add src/ to sys.path so we can import core.models
# =============================================================================
_THIS_DIR = Path(__file__).resolve().parent          # .../src/ui/statistic
_SRC_DIR = _THIS_DIR.parent.parent                    # .../src/
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from core.models import (
    Alert,
    AlertLevel,
    AttackCategory,
    DetectionResult,
    PacketInfo,
    Protocol,
)

# =============================================================================
# Colour palette — dark theme (matching packet_capture / behavior_detect)
# =============================================================================

CLR_BG_0          = "#1e1e1e"
CLR_BG_1          = "#2d2d2d"
CLR_BG_2          = "#3c3c3c"

CLR_BORDER        = "#3e3e3e"
CLR_BORDER_VIS    = "#555555"

CLR_TEXT          = "#d4d4d4"
CLR_TEXT_MUTED    = "#888888"
CLR_TEXT_INVERSE  = "#ffffff"

CLR_ACCENT        = "#007acc"
CLR_SECTION_BG    = "#252525"

CLR_SELECTION_BG  = "#094771"

# Clock-specific colours
CLR_MARKER_RED    = "#ff4444"   # HIGH / CRITICAL attack markers
CLR_MARKER_YELLOW = "#ffdd44"   # LOW / MEDIUM attack markers
CLR_CLOCK_FACE    = "#2a2a2a"   # clock circle fill
CLR_CLOCK_RING    = "#007acc"   # clock outer ring

# =============================================================================
# Reusable CSS templates
# =============================================================================

CSS_SPLITTER_HANDLE = (
    "QSplitter::handle {{ background-color: {CLR_BORDER}; }}"
)

CSS_TABLE = (
    "QTableWidget {{"
    "background-color: {CLR_BG_0}; color: {CLR_TEXT};"
    "gridline-color: {CLR_BORDER}; border: 1px solid {CLR_BORDER};"
    "font-size: 12px;"
    "}}"
    "QTableWidget::item {{ padding: 4px 8px; }}"
    "QTableWidget::item:selected {{"
    "background-color: {CLR_SELECTION_BG}; color: {CLR_TEXT_INVERSE};"
    "}}"
    "QHeaderView::section {{"
    "background-color: {CLR_SECTION_BG}; color: {CLR_TEXT};"
    "padding: 5px 8px; border: none;"
    "border-bottom: 2px solid {CLR_ACCENT}; font-weight: bold;"
    "}}"
)

CSS_SCROLL_AREA = (
    "QScrollArea {{ border: none; background-color: {CLR_BG_0}; }}"
    "QScrollBar:vertical {{ background: {CLR_BG_1}; width: 8px; }}"
    "QScrollBar::handle:vertical {{ background: {CLR_BORDER_VIS};"
    "border-radius: 4px; min-height: 30px; }}"
    "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}"
)

CSS_APP_GLOBAL = (
    "QMainWindow {{ background-color: {CLR_BG_0}; }}"
    "QToolTip {{"
    "background-color: {CLR_BG_1}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS};"
    "}}"
)


# =============================================================================
# AttackClockWidget — 24-hour circle clock with attack markers
# =============================================================================

class AttackClockWidget(QWidget):
    """Custom-painted 24-hour clock as a circle with:

    - 24 equally-spaced hour ticks (0..23), labelled at every hour
    - Centred HH:MM current-time display
    - Clickable attack markers (!) on the ring:
      * RED   → HIGH / CRITICAL
      * YELLOW → LOW / MEDIUM

    Maintains a square aspect ratio via ``heightForWidth``.
    """

    marker_clicked = pyqtSignal(object)  # emits an Alert

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMouseTracking(True)

        self._current_time: datetime = datetime.now()
        self._attacks: list[Alert] = []
        self._marker_rects: list[tuple[QRectF, Alert]] = []

    # ── Public API ──────────────────────────────────────────────────────────

    def set_time(self, dt: datetime) -> None:
        """Update the displayed current time and trigger a repaint."""
        self._current_time = dt
        self.update()

    def set_attacks(self, attacks: list[Alert]) -> None:
        """Replace all attack markers."""
        self._attacks = list(attacks)
        self.update()

    def clear_attacks(self) -> None:
        """Remove all attack markers."""
        self._attacks.clear()
        self.update()

    # ── Square aspect ───────────────────────────────────────────────────────

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, w: int) -> int:
        return w

    def sizeHint(self):
        from PyQt6.QtCore import QSize
        return QSize(400, 400)

    # ── Painting ────────────────────────────────────────────────────────────

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        side = min(w, h)
        cx, cy = w / 2.0, h / 2.0
        radius = side / 2.0 - 25  # 25 px padding

        # ---- background ----
        painter.fillRect(0, 0, w, h, QColor(CLR_BG_0))

        if radius < 40:
            painter.end()
            return  # too small to render meaningfully

        # ---- outer ring ----
        ring_pen = QPen(QColor(CLR_CLOCK_RING), 2)
        painter.setPen(ring_pen)
        painter.setBrush(QColor(CLR_CLOCK_FACE))
        painter.drawEllipse(QPointF(cx, cy), radius, radius)

        # ---- 24 hour ticks & digits ----
        major_hours = {0, 3, 6, 9, 12, 15, 18, 21}
        font_size = max(8, int(radius / 20))

        for hour in range(24):
            angle_deg = hour * 15               # 0-345 degrees
            angle_rad = math.radians(angle_deg - 90)  # 0 = top

            cos_a = math.cos(angle_rad)
            sin_a = math.sin(angle_rad)

            is_major = hour in major_hours

            # Tick line
            tick_inner = radius * (0.82 if is_major else 0.87)
            tick_outer = radius * 0.95

            x1 = cx + tick_inner * cos_a
            y1 = cy + tick_inner * sin_a
            x2 = cx + tick_outer * cos_a
            y2 = cy + tick_outer * sin_a

            painter.setPen(QPen(QColor(CLR_TEXT), 1.5 if is_major else 1))
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

            # Number label
            num_radius = radius * 0.75
            nx = cx + num_radius * cos_a
            ny = cy + num_radius * sin_a

            painter.setFont(QFont("Segoe UI", font_size))
            painter.setPen(QColor(CLR_TEXT_MUTED))

            text_rect = QRectF(
                nx - font_size * 3, ny - font_size * 1.5,
                font_size * 6, font_size * 3,
            )
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, str(hour))

        # ---- centre time display ----
        time_str = self._current_time.strftime("%H:%M")
        center_font_size = max(16, int(radius / 6))
        painter.setFont(
            QFont("Segoe UI", center_font_size, QFont.Weight.Bold))
        painter.setPen(QColor(CLR_TEXT))
        painter.drawText(
            QRectF(cx - radius * 0.3, cy - radius * 0.15,
                   radius * 0.6, radius * 0.3),
            Qt.AlignmentFlag.AlignCenter,
            time_str,
        )

        # ---- attack markers ----
        self._marker_rects.clear()
        marker_size = max(14, int(radius / 12))

        # Deduplicate markers at the same hour position
        seen_hours: set[int] = set()
        for alert in self._attacks:
            hour = self._timestamp_to_hour(alert.timestamp)
            # Offset overlapping markers slightly
            if hour in seen_hours:
                continue
            seen_hours.add(hour)

            angle_deg = hour * 15
            angle_rad = math.radians(angle_deg - 90)

            ma_x = cx + radius * 0.88 * math.cos(angle_rad)
            ma_y = cy + radius * 0.88 * math.sin(angle_rad)

            # Colour by alert level
            if alert.level in (AlertLevel.HIGH, AlertLevel.CRITICAL):
                marker_color = QColor(CLR_MARKER_RED)
            else:
                marker_color = QColor(CLR_MARKER_YELLOW)

            # Draw filled circle
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(marker_color)
            rect = QRectF(
                ma_x - marker_size / 2, ma_y - marker_size / 2,
                marker_size, marker_size,
            )
            painter.drawEllipse(rect)

            # Draw "!" inside
            exclaim_size = max(8, int(marker_size * 0.7))
            painter.setFont(
                QFont("Segoe UI", exclaim_size, QFont.Weight.Bold))
            painter.setPen(QColor(CLR_TEXT_INVERSE))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "!")

            # Store for hit-testing
            self._marker_rects.append((rect, alert))

        painter.end()

    # ── Mouse interaction ───────────────────────────────────────────────────

    def mousePressEvent(self, event) -> None:
        pos = event.position()
        for rect, alert in self._marker_rects:
            if rect.contains(pos):
                self.marker_clicked.emit(alert)
                return
        super().mousePressEvent(event)

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _timestamp_to_hour(ts: float) -> int:
        """Convert a Unix timestamp to the hour (0..23)."""
        try:
            return datetime.fromtimestamp(ts).hour
        except (OSError, ValueError, OverflowError):
            return 0


# =============================================================================
# AttackDetailPanel — right-upper table for attack details
# =============================================================================

class AttackDetailPanel(QWidget):
    """Table view showing details of a selected attack alert.

    Initially shows a placeholder: "NO DETECTION HAS BEEN LAUNCHED".
    Switches to a detail table when ``show_attack`` is called.
    """

    _COLUMNS: list[tuple[str, str]] = [
        ("time",        "Time"),
        ("level",       "Level"),
        ("category",    "Category"),
        ("src_ip",      "Source IP"),
        ("dst_ip",      "Dest IP"),
        ("protocol",    "Protocol"),
        ("rule_name",   "Rule"),
        ("description", "Description"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Section header
        header = QLabel("Attack Detail")
        header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        header.setStyleSheet(
            f"color: {CLR_TEXT}; background-color: {CLR_SECTION_BG};"
            f"padding: 8px 12px; border-bottom: 2px solid {CLR_ACCENT};"
        )
        outer.addWidget(header)

        # Stacked widget: table (0) | placeholder (1)
        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_table_page())
        self._stack.addWidget(self._build_placeholder_page())
        self._stack.setCurrentIndex(1)  # default: placeholder
        outer.addWidget(self._stack, stretch=1)

    # ── Build sub-pages ─────────────────────────────────────────────────────

    def _build_table_page(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels([c[1] for c in self._COLUMNS])
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(False)

        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        self._table.setStyleSheet(CSS_TABLE.format(
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT,
            CLR_BORDER=CLR_BORDER, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT,
            CLR_SELECTION_BG=CLR_SELECTION_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
        ))

        layout.addWidget(self._table)
        return container

    def _build_placeholder_page(self) -> QWidget:
        container = QWidget()
        container.setStyleSheet(f"background-color: {CLR_BG_0};")
        layout = QVBoxLayout(container)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel("NO DETECTION HAS BEEN LAUNCHED")
        lbl.setFont(QFont("Segoe UI", 14))
        lbl.setStyleSheet(f"color: {CLR_TEXT_MUTED};")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl)
        return container

    # ── Public API ──────────────────────────────────────────────────────────

    def show_attack(self, alert: Alert) -> None:
        """Populate the table with a single alert's fields."""
        self._table.setRowCount(0)
        self._table.insertRow(0)

        values: dict[str, str] = {
            "time": (
                datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
                if alert.timestamp else "—"
            ),
            "level": str(getattr(alert.level, "value", alert.level)),
            "category": str(getattr(alert.category, "value", alert.category)),
            "src_ip": alert.src_ip or "—",
            "dst_ip": alert.dst_ip or "—",
            "protocol": str(getattr(alert.protocol, "value", alert.protocol)),
            "rule_name": alert.rule_name or "—",
            "description": alert.description or "—",
        }

        for col, (key, _header) in enumerate(self._COLUMNS):
            item = QTableWidgetItem(values.get(key, "—"))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item.setForeground(QColor(CLR_TEXT))
            self._table.setItem(0, col, item)

        self._table.resizeColumnsToContents()
        self._stack.setCurrentIndex(0)

    def clear_display(self) -> None:
        """Return to the placeholder view."""
        self._table.setRowCount(0)
        self._stack.setCurrentIndex(1)


# =============================================================================
# IpRankingPanel — right-lower source-IP ranking
# =============================================================================

class IpRankingPanel(QWidget):
    """Table showing source-IP occurrence counts, sorted descending.

    Initially shows a placeholder: "NO CAPTURE HAS BEEN DEPLOYED".
    Switches to the ranking table when ``update_ranking`` receives packets.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Section header
        header = QLabel("Source IP Ranking")
        header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        header.setStyleSheet(
            f"color: {CLR_TEXT}; background-color: {CLR_SECTION_BG};"
            f"padding: 8px 12px; border-bottom: 2px solid {CLR_ACCENT};"
        )
        outer.addWidget(header)

        # Stacked widget: table (0) | placeholder (1)
        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_table_page())
        self._stack.addWidget(self._build_placeholder_page())
        self._stack.setCurrentIndex(1)  # default: placeholder
        outer.addWidget(self._stack, stretch=1)

    # ── Build sub-pages ─────────────────────────────────────────────────────

    def _build_table_page(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Rank", "Source IP", "Count"])
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(False)

        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        self._table.setStyleSheet(CSS_TABLE.format(
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT,
            CLR_BORDER=CLR_BORDER, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT,
            CLR_SELECTION_BG=CLR_SELECTION_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
        ))

        layout.addWidget(self._table)
        return container

    def _build_placeholder_page(self) -> QWidget:
        container = QWidget()
        container.setStyleSheet(f"background-color: {CLR_BG_0};")
        layout = QVBoxLayout(container)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel("NO CAPTURE HAS BEEN DEPLOYED")
        lbl.setFont(QFont("Segoe UI", 14))
        lbl.setStyleSheet(f"color: {CLR_TEXT_MUTED};")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl)
        return container

    # ── Public API ──────────────────────────────────────────────────────────

    def update_ranking(self, packets: list[PacketInfo]) -> None:
        """Rebuild the ranking table from a list of PacketInfo objects."""
        # Count source IPs
        counts: dict[str, int] = {}
        for pkt in packets:
            if pkt.src_ip:
                counts[pkt.src_ip] = counts.get(pkt.src_ip, 0) + 1

        sorted_ips = sorted(counts.items(), key=lambda kv: -kv[1])

        self._table.setRowCount(0)
        for rank, (ip, cnt) in enumerate(sorted_ips, 1):
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._set_cell(row, 0, str(rank))
            self._set_cell(row, 1, ip)
            self._set_cell(row, 2, str(cnt))

        if sorted_ips:
            self._stack.setCurrentIndex(0)

    def clear_display(self) -> None:
        """Return to the placeholder view."""
        self._table.setRowCount(0)
        self._stack.setCurrentIndex(1)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _set_cell(self, row: int, col: int,
                  text: str) -> QTableWidgetItem | None:
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setForeground(QColor(CLR_TEXT))
        self._table.setItem(row, col, item)
        return item


# =============================================================================
# StatisticWindow — top-level composite window
# =============================================================================

class StatisticWindow(QMainWindow):
    """Main window: left clock | right-upper attack detail | right-lower IP ranking.

    A background ``QTimer`` (1 s interval) generates mock detection alerts
    and packets so the display always has data.  External modules can feed
    **real** data via the public ``add_alert`` and ``add_packet`` methods.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Statistics — Network Attack Detector")
        self.resize(1100, 700)

        # Data stores
        self._attacks: list[Alert] = []
        self._packets: list[PacketInfo] = []

        # Mock-data control — when True the timer generates synthetic data;
        # set to False when external modules feed real data via add_alert/add_packet.
        self._use_mock_data: bool = True

        # Simulation counter
        self._sim_counter: int = 0

        # Data-collection timer (always runs — updates clock + refreshes panels)
        self._data_timer = QTimer(self)
        self._data_timer.setInterval(1000)

        self._build_ui()
        self._connect_signals()

        # Start collecting immediately
        self._data_timer.start()

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Horizontal splitter (clock | vertical splitter)."""
        self._h_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._h_splitter.setHandleWidth(3)
        self._h_splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(
            CLR_BORDER=CLR_BORDER))

        # Left — clock (square)
        self._clock = AttackClockWidget()

        # ---- GEN REPORT button (top-left corner of the clock) ----
        self._gen_report_btn = QPushButton("GEN REPORT", self._clock)
        self._gen_report_btn.setStyleSheet(
            "QPushButton {"
            "background-color: #007acc; color: #ffffff;"
            "font-weight: bold; font-size: 12px;"
            "padding: 6px 14px; border: none; border-radius: 4px;"
            "}"
            "QPushButton:hover { background-color: #0098e8; }"
            "QPushButton:pressed { background-color: #005f9e; }"
        )
        self._gen_report_btn.move(8, 8)
        self._gen_report_btn.setFixedSize(130, 32)

        # -- Dropdown menu --
        report_menu = QMenu(self._gen_report_btn)
        report_menu.setStyleSheet(
            "QMenu {"
            "background-color: #000000; color: #ffffff;"
            "border: 1px solid #3e3e3e; padding: 4px 0;"
            "}"
            "QMenu::item {"
            "padding: 8px 24px;"
            "}"
            "QMenu::item:selected {"
            "background-color: #007acc;"
            "}"
        )

        csv_action = report_menu.addAction("GEN CSV REPORT")
        html_action = report_menu.addAction("GEN HTML REPORT")

        csv_action.triggered.connect(self._on_gen_csv_report)
        html_action.triggered.connect(self._on_gen_html_report)

        self._gen_report_btn.setMenu(report_menu)

        self._h_splitter.addWidget(self._clock)

        # Right — vertical splitter (attack detail | IP ranking)
        self._v_splitter = QSplitter(Qt.Orientation.Vertical)
        self._v_splitter.setHandleWidth(3)
        self._v_splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(
            CLR_BORDER=CLR_BORDER))

        self._detail_panel = AttackDetailPanel()
        self._v_splitter.addWidget(self._detail_panel)

        self._ranking_panel = IpRankingPanel()
        self._v_splitter.addWidget(self._ranking_panel)

        self._v_splitter.setSizes([350, 350])
        self._h_splitter.addWidget(self._v_splitter)

        # Give the clock ~400 px, the right panels the rest
        self._h_splitter.setSizes([400, 700])

        self.setCentralWidget(self._h_splitter)

    # ── Signal wiring ───────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self._data_timer.timeout.connect(self._on_data_tick)
        self._clock.marker_clicked.connect(self._detail_panel.show_attack)

    # ── Data collection ─────────────────────────────────────────────────────

    def _on_data_tick(self) -> None:
        """Called every 1 000 ms.  Generates mock data (when enabled) and updates
        all panels with whatever data is available (mock or externally-fed)."""
        self._sim_counter += 1
        now = time.time()

        if self._use_mock_data:
            # -- Generate attacks every 3-7 seconds --
            if self._sim_counter % random.randint(3, 7) == 0:
                alerts = self._generate_mock_attacks(now)
                self._attacks.extend(alerts)

            # -- Generate packets every tick --
            packets = self._generate_mock_packets(now)
            self._packets.extend(packets)

        # -- Bound data sizes --
        if len(self._attacks) > 200:
            self._attacks = self._attacks[-200:]
        if len(self._packets) > 1000:
            self._packets = self._packets[-1000:]

        # -- Update UI (always — reflects both mock and real data) --
        self._clock.set_time(datetime.now())
        self._clock.set_attacks(self._attacks)
        self._ranking_panel.update_ranking(self._packets)

    # ── Mock data generators ────────────────────────────────────────────────

    def _generate_mock_attacks(self, now: float) -> list[Alert]:
        """Create 1-3 synthetic alerts mimicking detection-module output."""
        categories = list(AttackCategory)
        levels = [
            AlertLevel.LOW, AlertLevel.MEDIUM,
            AlertLevel.HIGH, AlertLevel.CRITICAL,
        ]
        src_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.100", "172.16.0.50"]
        dst_ips = ["10.0.0.10", "192.168.1.1", "10.0.0.254"]

        count = random.randint(1, 3)
        result: list[Alert] = []
        for i in range(count):
            cat = random.choice(categories)
            level = random.choice(levels)
            result.append(Alert(
                alert_id=f"STAT-A-{self._sim_counter:06d}-{i}",
                timestamp=now,
                category=cat,
                level=level,
                src_ip=random.choice(src_ips),
                dst_ip=random.choice(dst_ips),
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([22, 80, 443, 3306, 8080]),
                protocol=random.choice([Protocol.TCP, Protocol.UDP]),
                rule_id=f"RULE-{random.randint(1000, 9999)}",
                rule_name=f"Mock Rule {random.randint(1, 20)}",
                evidence=(
                    f"Suspicious {cat.value} pattern in "
                    f"packet STAT-PKT-{self._sim_counter:06d}"
                ),
                description=(
                    f"Simulated {cat.value} attack ({level.value})"
                ),
                suggestion=(
                    "Investigate source IP and review logs"
                    if random.random() > 0.3 else ""
                ),
            ))
        return result

    def _generate_mock_packets(self, now: float) -> list[PacketInfo]:
        """Create 1-3 synthetic packets mimicking packet-capture output."""
        # Weighted source IPs so some dominate the ranking
        src_ip_pool = [
            "192.168.1.10", "192.168.1.10",
            "192.168.1.20", "192.168.1.20",
            "192.168.1.20",
            "10.0.0.5", "10.0.0.15",
            "172.16.0.1", "192.168.1.100",
        ]
        dst_ips = ["10.0.0.10", "192.168.1.1", "8.8.8.8"]

        count = random.randint(1, 3)
        result: list[PacketInfo] = []
        for i in range(count):
            src_ip = random.choice(src_ip_pool)
            is_tcp_or_udp = random.random() > 0.3
            proto = (
                random.choice([Protocol.TCP, Protocol.UDP])
                if is_tcp_or_udp else Protocol.ICMP
            )
            result.append(PacketInfo(
                packet_id=f"STAT-PKT-{self._sim_counter:06d}-{i}",
                timestamp=now,
                src_ip=src_ip,
                dst_ip=random.choice(dst_ips),
                src_port=(
                    random.randint(1024, 65535) if is_tcp_or_udp else None
                ),
                dst_port=(
                    random.choice([22, 80, 443]) if is_tcp_or_udp else None
                ),
                protocol=proto,
                length=random.randint(40, 1500),
            ))
        return result

    # ── Public integration API ──────────────────────────────────────────────

    def set_use_mock_data(self, use_mock: bool) -> None:
        """Enable or disable automatic mock-data generation.

        When *use_mock* is ``False`` the timer still ticks (to refresh the
        clock and re-render panels), but no synthetic alerts or packets are
        generated.  External modules should feed real data via
        :meth:`add_alert` and :meth:`add_packet` instead.
        """
        self._use_mock_data = use_mock

    def add_alert(self, alert: Alert) -> None:
        """Receive an ``Alert`` from an external detection module.

        Call this from ``behavior_detector`` or ``feature_detect`` when
        a real detection fires, e.g.::

            stat_window.add_alert(alert)
        """
        self._attacks.append(alert)
        if len(self._attacks) > 200:
            self._attacks = self._attacks[-200:]

    def add_packet(self, packet: PacketInfo) -> None:
        """Receive a ``PacketInfo`` from ``packet_capture``.

        Call this from ``packet_capture`` whenever a packet is captured,
        e.g.::

            stat_window.add_packet(packet_info)
        """
        self._packets.append(packet)
        if len(self._packets) > 1000:
            self._packets = self._packets[-1000:]

    # ── Report generation ────────────────────────────────────────────────────

    def _on_gen_csv_report(self) -> None:
        """Handle **GEN CSV REPORT** menu action.

        Delegates to :func:`report.csv_exporter.generate_attack_report`
        with the current attack-alert list.
        """
        from report.csv_exporter import generate_attack_report

        generate_attack_report(self._attacks, self)

    def _on_gen_html_report(self) -> None:
        """Handle **GEN HTML REPORT** menu action.

        Delegates to :func:`report.html_reporter.generate_overall_report`
        with both alert and packet data.
        """
        from report.html_reporter import generate_overall_report

        generate_overall_report(self._attacks, self._packets, self)

    # ── Close event ─────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        self._data_timer.stop()
        event.accept()


# =============================================================================
# Entry point
# =============================================================================

def main() -> None:
    """Launch the statistics composite window."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    app.setStyleSheet(CSS_APP_GLOBAL.format(
        CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1,
        CLR_TEXT=CLR_TEXT, CLR_BORDER_VIS=CLR_BORDER_VIS,
        CLR_BORDER=CLR_BORDER,
    ))

    window = StatisticWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
