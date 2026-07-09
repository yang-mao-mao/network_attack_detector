"""Statistics panel with embedded matplotlib charts.

Provides:
- StatsPanel: QWidget containing a pie chart (attack category distribution),
  a horizontal bar chart (Top 10 source IPs), a line chart (alert timeline),
  and a summary metrics section.
- StatsPanelModel: static helper methods for aggregating alert data.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from src.core.models import Alert

# ── matplotlib backend (must be set before pyplot import) ──────────────────

import matplotlib  # noqa: E402

matplotlib.use("QtAgg")

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

# Matplotlib 中文字体设置
matplotlib.rcParams["font.sans-serif"] = [
    "WenQuanYi Micro Hei",
    "WenQuanYi Zen Hei",
    "Noto Sans CJK SC",
    "SimHei",
    "DejaVu Sans",
]
matplotlib.rcParams["axes.unicode_minus"] = False

# ── colour palette ────────────────────────────────────────────────────────

CATEGORY_COLORS: dict[str, str] = {
    "SQL Injection": "#E74C3C",
    "XSS": "#E67E22",
    "Command Injection": "#9B59B6",
    "WebShell": "#8E44AD",
    "Brute Force": "#2ECC71",
    "Port Scan": "#3498DB",
    "Malware": "#F1C40F",
    "Suspicious Traffic": "#1ABC9C",
    "Unknown": "#95A5A6",
}


class StatsPanelModel:
    """Static helpers for aggregating :class:`Alert` data."""

    @staticmethod
    def count_by_category(alerts: list[Alert]) -> dict[str, int]:
        return dict(Counter(alert.category.value for alert in alerts))

    @staticmethod
    def count_by_src_ip(alerts: list[Alert]) -> dict[str, int]:
        return dict(Counter(alert.src_ip or "N/A" for alert in alerts))

    @staticmethod
    def count_by_time(alerts: list[Alert], window_minutes: int = 60) -> dict[str, int]:
        """Bucket alert counts by minute for the last *window_minutes*.

        Returns a dict of ``"HH:MM" -> count`` with zero-filled buckets.
        """
        now = datetime.now()
        start = now - timedelta(minutes=window_minutes)
        buckets: dict[str, int] = {}
        cursor = start.replace(second=0, microsecond=0)
        while cursor <= now:
            buckets[cursor.strftime("%H:%M")] = 0
            cursor += timedelta(minutes=1)

        for alert in alerts:
            ts = datetime.fromtimestamp(alert.timestamp)
            if ts < start:
                continue
            key = ts.strftime("%H:%M")
            buckets[key] = buckets.get(key, 0) + 1
        return buckets

    @staticmethod
    def count_critical_by_time(alerts: list[Alert], window_minutes: int = 60) -> dict[str, int]:
        """Same as count_by_time but only for Critical alerts."""
        from src.core.models import AlertLevel

        critical = [a for a in alerts if a.level == AlertLevel.CRITICAL]
        return StatsPanelModel.count_by_time(critical, window_minutes)

    @staticmethod
    def count_high_by_time(alerts: list[Alert], window_minutes: int = 60) -> dict[str, int]:
        """Same as count_by_time but only for High alerts."""
        from src.core.models import AlertLevel

        high = [a for a in alerts if a.level == AlertLevel.HIGH]
        return StatsPanelModel.count_by_time(high, window_minutes)


# ── StatsPanel widget ─────────────────────────────────────────────────────


class StatsPanel(QWidget):
    """Embedded statistics dashboard with three charts and a summary section."""

    _REFRESH_INTERVAL_MS = 5000  # 5 seconds

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._alerts: list[Alert] = []
        self._packet_count: int = 0
        self._setup_ui()

        # periodic refresh timer
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._redraw)
        self._refresh_timer.start(self._REFRESH_INTERVAL_MS)

    # ── setup ─────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(6)

        # --- charts row ---
        charts_layout = QHBoxLayout()

        # pie chart — attack category distribution
        self._pie_fig = Figure(figsize=(3.5, 2.8), dpi=100)
        self._pie_canvas = FigureCanvas(self._pie_fig)
        self._pie_ax = self._pie_fig.add_subplot(111)
        pie_group = self._wrap_chart("攻击类型分布", self._pie_canvas)
        charts_layout.addWidget(pie_group)

        # bar chart — Top 10 source IPs
        self._bar_fig = Figure(figsize=(3.5, 2.8), dpi=100)
        self._bar_canvas = FigureCanvas(self._bar_fig)
        self._bar_ax = self._bar_fig.add_subplot(111)
        bar_group = self._wrap_chart("Top 10 攻击源 IP", self._bar_canvas)
        charts_layout.addWidget(bar_group)

        main_layout.addLayout(charts_layout)

        # --- line chart row (full width) ---
        self._line_fig = Figure(figsize=(7, 2.5), dpi=100)
        self._line_canvas = FigureCanvas(self._line_fig)
        self._line_ax = self._line_fig.add_subplot(111)
        line_group = self._wrap_chart("告警时间趋势 (最近 60 分钟)", self._line_canvas)
        main_layout.addWidget(line_group)

        # --- summary metrics ---
        metrics_layout = QHBoxLayout()

        self._total_alerts_label = QLabel("总告警: 0")
        self._total_packets_label = QLabel("总流量: 0")
        self._detection_rate_label = QLabel("检测率: 0.00%")
        self._top_attacker_label = QLabel("最活跃攻击者: -")
        self._top_category_label = QLabel("最常见攻击: -")

        for lbl in [
            self._total_alerts_label,
            self._total_packets_label,
            self._detection_rate_label,
            self._top_attacker_label,
            self._top_category_label,
        ]:
            lbl.setStyleSheet("font-size: 12px; padding: 2px 8px;")
            metrics_layout.addWidget(lbl)

        metrics_layout.addStretch()
        main_layout.addLayout(metrics_layout)

    @staticmethod
    def _wrap_chart(title: str, canvas: FigureCanvas) -> QGroupBox:
        """Wrap a matplotlib canvas in a group box with a title."""
        box = QGroupBox(title)
        box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(box)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.addWidget(canvas)
        return box

    # ── public API ────────────────────────────────────────────────────

    def update_with_alerts(self, alerts: list[Alert]) -> None:
        """Replace the internal alert list and schedule a redraw."""
        self._alerts = list(alerts)
        self._redraw()

    def update_with_packets(self, count: int) -> None:
        """Update the cumulative packet counter."""
        self._packet_count = count

    def add_alerts(self, alerts: list[Alert]) -> None:
        """Append new alerts incrementally (for real-time use)."""
        self._alerts.extend(alerts)
        # trim to keep memory bounded
        if len(self._alerts) > 10000:
            self._alerts = self._alerts[-10000:]

    def add_packet_count(self, delta: int = 1) -> None:
        """Increment the packet counter."""
        self._packet_count += delta

    def clear(self) -> None:
        """Reset all statistics."""
        self._alerts.clear()
        self._packet_count = 0
        self._redraw()

    # ── drawing ───────────────────────────────────────────────────────

    def _redraw(self) -> None:
        self._draw_pie()
        self._draw_bar()
        self._draw_line()
        self._update_metrics()
        # trigger canvas repaint
        self._pie_canvas.draw_idle()
        self._bar_canvas.draw_idle()
        self._line_canvas.draw_idle()

    def _draw_pie(self) -> None:
        self._pie_ax.clear()
        if not self._alerts:
            self._pie_ax.text(
                0.5, 0.5, "暂无数据", ha="center", va="center", transform=self._pie_ax.transAxes
            )
            self._pie_ax.set_title("攻击类型分布")
            return

        cat_counts = StatsPanelModel.count_by_category(self._alerts)
        labels = list(cat_counts.keys())
        sizes = list(cat_counts.values())
        colors = [CATEGORY_COLORS.get(l, "#95A5A6") for l in labels]

        wedges, texts, autotexts = self._pie_ax.pie(
            sizes,
            labels=None,
            autopct="%1.1f%%",
            startangle=90,
            colors=colors,
            textprops={"fontsize": 7},
        )
        self._pie_ax.legend(
            wedges,
            [f"{l} ({c})" for l, c in zip(labels, sizes)],
            loc="lower center",
            bbox_to_anchor=(0.5, -0.15),
            fontsize=6,
            ncol=2,
        )
        self._pie_ax.set_title("攻击类型分布", fontsize=10)

    def _draw_bar(self) -> None:
        self._bar_ax.clear()
        if not self._alerts:
            self._bar_ax.text(
                0.5, 0.5, "暂无数据", ha="center", va="center", transform=self._bar_ax.transAxes
            )
            self._bar_ax.set_title("Top 10 攻击源 IP")
            return

        ip_counts = StatsPanelModel.count_by_src_ip(self._alerts)
        top10 = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ips = [ip for ip, _ in top10]
        counts = [c for _, c in top10]

        bars = self._bar_ax.barh(range(len(ips)), counts, color="#3498DB", height=0.6)
        self._bar_ax.set_yticks(range(len(ips)))
        self._bar_ax.set_yticklabels(ips, fontsize=7)
        self._bar_ax.invert_yaxis()  # highest count at top
        self._bar_ax.set_xlabel("告警数量", fontsize=8)
        self._bar_ax.set_title("Top 10 攻击源 IP", fontsize=10)

        for bar, count in zip(bars, counts):
            self._bar_ax.text(
                bar.get_width() + 0.3,
                bar.get_y() + bar.get_height() / 2,
                str(count),
                va="center",
                fontsize=7,
            )

    def _draw_line(self) -> None:
        self._line_ax.clear()
        if not self._alerts:
            self._line_ax.text(
                0.5, 0.5, "暂无数据", ha="center", va="center", transform=self._line_ax.transAxes
            )
            self._line_ax.set_title("告警时间趋势 (最近 60 分钟)")
            return

        total_buckets = StatsPanelModel.count_by_time(self._alerts)
        critical_buckets = StatsPanelModel.count_critical_by_time(self._alerts)
        high_buckets = StatsPanelModel.count_high_by_time(self._alerts)

        times = list(total_buckets.keys())
        x = range(len(times))

        self._line_ax.plot(x, [total_buckets[t] for t in times], "b-", label="总告警", linewidth=1.2)
        self._line_ax.plot(
            x, [critical_buckets[t] for t in times], "r-", label="Critical", linewidth=1.0
        )
        self._line_ax.plot(
            x, [high_buckets[t] for t in times], color="orange", label="High", linewidth=1.0
        )

        # show every ~10th tick label to avoid crowding
        step = max(1, len(times) // 10)
        self._line_ax.set_xticks(list(x)[::step])
        self._line_ax.set_xticklabels(times[::step], fontsize=6, rotation=45)

        self._line_ax.set_ylabel("告警数", fontsize=8)
        self._line_ax.set_title("告警时间趋势 (最近 60 分钟)", fontsize=10)
        self._line_ax.legend(fontsize=7, loc="upper right")
        self._line_ax.grid(True, alpha=0.3)

    def _update_metrics(self) -> None:
        total = len(self._alerts)
        rate = (total / self._packet_count * 100) if self._packet_count > 0 else 0.0

        self._total_alerts_label.setText(f"总告警: {total}")
        self._total_packets_label.setText(f"总流量: {self._packet_count}")
        self._detection_rate_label.setText(f"检测率: {rate:.2f}%")

        if self._alerts:
            ip_counts = StatsPanelModel.count_by_src_ip(self._alerts)
            top_ip, top_ip_count = max(ip_counts.items(), key=lambda x: x[1])
            self._top_attacker_label.setText(f"最活跃攻击者: {top_ip} ({top_ip_count}次)")

            cat_counts = StatsPanelModel.count_by_category(self._alerts)
            top_cat, top_cat_count = max(cat_counts.items(), key=lambda x: x[1])
            self._top_category_label.setText(f"最常见攻击: {top_cat} ({top_cat_count}次)")
        else:
            self._top_attacker_label.setText("最活跃攻击者: -")
            self._top_category_label.setText("最常见攻击: -")
