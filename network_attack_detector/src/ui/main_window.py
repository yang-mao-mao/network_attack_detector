"""Main application window for the Network Attack Detector.

Provides:
- MainWindow: QMainWindow subclass that integrates all UI panels (traffic
  table, alert table, rule panel, stats panel), a menu bar, a toolbar, and
  a status bar.

The window uses PyQt6 as the GUI framework, matplotlib for in-app charts
(embedded in StatsPanel), and delegates HTML/CSV export to the report layer.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from src.core.event_bus import EventBus
from src.core.models import Alert, PacketInfo
from src.report.csv_exporter import CsvExporter
from src.report.html_reporter import HtmlReporter
from src.rules.rule_manager import RuleManager
from src.ui.alert_table import AlertTableView
from src.ui.rule_panel import RulePanel
from src.ui.stats_panel import StatsPanel
from src.ui.traffic_table import TrafficTableView

if TYPE_CHECKING:
    pass


class MainWindow(QMainWindow):
    """Main application window.

    Slots are wired to :class:`EventBus` events so that capture and detection
    modules can feed data into the UI without direct coupling.

    Parameters
    ----------
    event_bus:
        Shared event bus for receiving ``packet_captured``, ``alert_generated``,
        ``capture_error``, and other events.
    rule_manager:
        Rule manager instance for the rule panel.
    parent:
        Optional parent widget.
    """

    #: Emitted when the user requests capture start on a specific interface.
    capture_start_requested = pyqtSignal(str)
    #: Emitted when the user requests capture stop.
    capture_stop_requested = pyqtSignal()
    #: Emitted when the user requests a pcap file to be loaded.
    pcap_file_requested = pyqtSignal(str)

    def __init__(
        self,
        event_bus: EventBus | None = None,
        rule_manager: RuleManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._event_bus = event_bus or EventBus()
        self._rule_manager = rule_manager or RuleManager()
        self._capture_running = False
        self._capture_paused = False
        self._start_time: float | None = None
        self._packet_count = 0
        self._alert_count = 0

        self.setWindowTitle("Network Attack Detector — 网络攻击检测系统")
        self.resize(1400, 900)

        self._setup_central()
        self._setup_menu_bar()
        self._setup_toolbar()
        self._setup_status_bar()
        self._subscribe_events()

        # periodic status bar update
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_timer.start(1000)

    # ═══════════════════════════════════════════════════════════════════
    # Central widget layout
    # ═══════════════════════════════════════════════════════════════════

    def _setup_central(self) -> None:
        """Build the central widget with a vertical splitter.

        Top half: traffic table (left) + alert table (right).
        Bottom half: tab widget with stats panel and rule panel.
        """
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)

        # --- top splitter: traffic | alerts ---
        top_splitter = QSplitter(Qt.Orientation.Horizontal)

        self._traffic_table = TrafficTableView()
        top_splitter.addWidget(self._traffic_table)

        self._alert_table = AlertTableView()
        top_splitter.addWidget(self._alert_table)

        top_splitter.setStretchFactor(0, 6)  # traffic gets 60 %
        top_splitter.setStretchFactor(1, 4)  # alerts  get 40 %
        top_splitter.setSizes([800, 500])

        root.addWidget(top_splitter, stretch=3)

        # --- bottom tabs: stats + rules ---
        bottom_tabs = QTabWidget()

        self._stats_panel = StatsPanel()
        bottom_tabs.addTab(self._stats_panel, "📊 统计图表")

        self._rule_panel = RulePanel()
        self._rule_panel.set_rule_manager(self._rule_manager)
        bottom_tabs.addTab(self._rule_panel, "📋 规则管理")

        root.addWidget(bottom_tabs, stretch=2)

    # ═══════════════════════════════════════════════════════════════════
    # Menu bar
    # ═══════════════════════════════════════════════════════════════════

    def _setup_menu_bar(self) -> None:
        mb = self.menuBar()

        # --- File ---
        file_menu = mb.addMenu("文件(&F)")

        export_csv_action = QAction("导出告警 CSV...", self)
        export_csv_action.setShortcut(QKeySequence("Ctrl+E"))
        export_csv_action.triggered.connect(self._export_csv)
        file_menu.addAction(export_csv_action)

        export_html_action = QAction("导出 HTML 报告...", self)
        export_html_action.setShortcut(QKeySequence("Ctrl+H"))
        export_html_action.triggered.connect(self._export_html)
        file_menu.addAction(export_html_action)

        export_charts_action = QAction("导出图表 (pyecharts)...", self)
        export_charts_action.setShortcut(QKeySequence("Ctrl+G"))
        export_charts_action.triggered.connect(self._export_pyecharts)
        file_menu.addAction(export_charts_action)

        file_menu.addSeparator()

        exit_action = QAction("退出(&X)", self)
        exit_action.setShortcut(QKeySequence("Alt+F4"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # --- Capture ---
        capture_menu = mb.addMenu("抓包(&C)")

        self._start_action = QAction("开始抓包", self)
        self._start_action.setShortcut(QKeySequence("F5"))
        self._start_action.triggered.connect(self._on_start_capture)
        capture_menu.addAction(self._start_action)

        self._stop_action = QAction("停止抓包", self)
        self._stop_action.setShortcut(QKeySequence("F6"))
        self._stop_action.setEnabled(False)
        self._stop_action.triggered.connect(self._on_stop_capture)
        capture_menu.addAction(self._stop_action)

        self._pause_action = QAction("暂停抓包", self)
        self._pause_action.setShortcut(QKeySequence("F7"))
        self._pause_action.setEnabled(False)
        self._pause_action.triggered.connect(self._on_pause_capture)
        capture_menu.addAction(self._pause_action)

        capture_menu.addSeparator()

        open_pcap_action = QAction("打开 pcap 文件...", self)
        open_pcap_action.setShortcut(QKeySequence("Ctrl+O"))
        open_pcap_action.triggered.connect(self._on_open_pcap)
        capture_menu.addAction(open_pcap_action)

        # --- Rules ---
        rules_menu = mb.addMenu("规则(&R)")

        reload_action = QAction("重新加载规则", self)
        reload_action.setShortcut(QKeySequence("Ctrl+R"))
        reload_action.triggered.connect(self._on_reload_rules)
        rules_menu.addAction(reload_action)

        # --- View ---
        view_menu = mb.addMenu("视图(&V)")

        self._show_traffic_action = QAction("显示/隐藏流量表", self)
        self._show_traffic_action.setCheckable(True)
        self._show_traffic_action.setChecked(True)
        self._show_traffic_action.triggered.connect(self._on_toggle_traffic)
        view_menu.addAction(self._show_traffic_action)

        self._show_stats_action = QAction("显示/隐藏统计", self)
        self._show_stats_action.setCheckable(True)
        self._show_stats_action.setChecked(True)
        self._show_stats_action.triggered.connect(self._on_toggle_stats)
        view_menu.addAction(self._show_stats_action)

        view_menu.addSeparator()

        clear_alerts_action = QAction("清除告警列表", self)
        clear_alerts_action.triggered.connect(self._on_clear_alerts)
        view_menu.addAction(clear_alerts_action)

        # --- Help ---
        help_menu = mb.addMenu("帮助(&H)")

        about_action = QAction("关于", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    # ═══════════════════════════════════════════════════════════════════
    # Toolbar
    # ═══════════════════════════════════════════════════════════════════

    def _setup_toolbar(self) -> None:
        tb = QToolBar("主工具栏")
        tb.setMovable(False)
        self.addToolBar(tb)

        tb.addWidget(QLabel(" 网卡: "))

        self._interface_combo = QComboBox()
        self._interface_combo.setMinimumWidth(180)
        self._interface_combo.setEditable(False)
        # placeholder — real interface list populated by capture module
        self._interface_combo.addItem("(自动选择)", "")
        tb.addWidget(self._interface_combo)

        tb.addSeparator()

        self._start_btn = QPushButton("▶ 开始抓包")
        self._start_btn.setStyleSheet(
            "QPushButton { background-color: #27AE60; color: white; padding: 4px 12px; }"
        )
        self._start_btn.clicked.connect(self._on_start_capture)
        tb.addWidget(self._start_btn)

        self._stop_btn = QPushButton("■ 停止")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "QPushButton { background-color: #E74C3C; color: white; padding: 4px 12px; }"
        )
        self._stop_btn.clicked.connect(self._on_stop_capture)
        tb.addWidget(self._stop_btn)

        self._pause_btn = QPushButton("⏸ 暂停")
        self._pause_btn.setEnabled(False)
        self._pause_btn.clicked.connect(self._on_pause_capture)
        tb.addWidget(self._pause_btn)

        tb.addSeparator()

        export_btn = QPushButton("📄 导出 CSV")
        export_btn.clicked.connect(self._export_csv)
        tb.addWidget(export_btn)

    # ═══════════════════════════════════════════════════════════════════
    # Status bar
    # ═══════════════════════════════════════════════════════════════════

    def _setup_status_bar(self) -> None:
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

        self._status_indicator = QLabel("⚫ 已停止")
        self._status_indicator.setStyleSheet(
            "QLabel { color: #7F8C8D; font-weight: bold; padding: 0 8px; }"
        )
        self._status_bar.addPermanentWidget(self._status_indicator)

        self._packet_count_label = QLabel("数据包: 0")
        self._status_bar.addPermanentWidget(self._packet_count_label)

        self._alert_count_label = QLabel("告警: 0")
        self._status_bar.addPermanentWidget(self._alert_count_label)

        self._uptime_label = QLabel("运行时间: 00:00:00")
        self._status_bar.addPermanentWidget(self._uptime_label)

    # ═══════════════════════════════════════════════════════════════════
    # Event bus wiring
    # ═══════════════════════════════════════════════════════════════════

    def _subscribe_events(self) -> None:
        self._event_bus.subscribe("packet_captured", self._on_packet)
        self._event_bus.subscribe("alert_generated", self._on_alert)
        self._event_bus.subscribe("capture_started", self._on_capture_started)
        self._event_bus.subscribe("capture_stopped", self._on_capture_stopped)
        self._event_bus.subscribe("capture_error", self._on_capture_error)

    # ═══════════════════════════════════════════════════════════════════
    # Event callbacks
    # ═══════════════════════════════════════════════════════════════════

    def _on_packet(self, payload: object) -> None:
        """Handle a ``packet_captured`` event."""
        if isinstance(payload, PacketInfo):
            self._traffic_table.add_packet(payload)
            self._packet_count += 1
            self._stats_panel.add_packet_count(1)

    def _on_alert(self, payload: object) -> None:
        """Handle an ``alert_generated`` event."""
        if isinstance(payload, Alert):
            self._alert_table.add_alert(payload)
            self._alert_count += 1
            self._stats_panel.add_alerts([payload])

    def _on_capture_started(self, _payload: object) -> None:
        self._capture_running = True
        self._capture_paused = False
        self._start_time = None  # will be set on first packet
        self._update_capture_ui_state()

    def _on_capture_stopped(self, _payload: object) -> None:
        self._capture_running = False
        self._capture_paused = False
        self._update_capture_ui_state()

    def _on_capture_error(self, payload: object) -> None:
        msg = str(payload) if payload else "未知抓包错误"
        QMessageBox.warning(self, "抓包错误", msg)

    # ═══════════════════════════════════════════════════════════════════
    # Slot: capture control
    # ═══════════════════════════════════════════════════════════════════

    def _on_start_capture(self) -> None:
        iface = self._interface_combo.currentData() or ""
        self.capture_start_requested.emit(iface)
        # If no external listener, simulate started state
        if not self._event_bus._handlers.get("capture_started"):
            self._on_capture_started(None)

    def _on_stop_capture(self) -> None:
        self.capture_stop_requested.emit()
        if not self._event_bus._handlers.get("capture_stopped"):
            self._on_capture_stopped(None)

    def _on_pause_capture(self) -> None:
        self._capture_paused = not self._capture_paused
        self._pause_btn.setText("▶ 恢复" if self._capture_paused else "⏸ 暂停")
        self._pause_action.setText("恢复抓包" if self._capture_paused else "暂停抓包")

    def _update_capture_ui_state(self) -> None:
        running = self._capture_running
        self._start_action.setEnabled(not running)
        self._start_btn.setEnabled(not running)
        self._stop_action.setEnabled(running)
        self._stop_btn.setEnabled(running)
        self._pause_action.setEnabled(running)
        self._pause_btn.setEnabled(running)
        self._interface_combo.setEnabled(not running)

    # ═══════════════════════════════════════════════════════════════════
    # Slot: export
    # ═══════════════════════════════════════════════════════════════════

    def _export_csv(self) -> None:
        alerts = self._alert_table.get_alerts()
        if not alerts:
            QMessageBox.information(self, "导出", "当前没有告警可导出。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出告警 CSV", "alerts.csv", "CSV 文件 (*.csv)"
        )
        if path:
            CsvExporter().export(alerts, path)
            QMessageBox.information(self, "导出成功", f"已导出 {len(alerts)} 条告警到:\n{path}")

    def _export_html(self) -> None:
        alerts = self._alert_table.get_alerts()
        if not alerts:
            QMessageBox.information(self, "导出", "当前没有告警可导出。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 HTML 报告", "report.html", "HTML 文件 (*.html)"
        )
        if path:
            HtmlReporter().export(alerts, path)
            QMessageBox.information(self, "导出成功", f"已导出 {len(alerts)} 条告警到:\n{path}")

    def _export_pyecharts(self) -> None:
        """Export an interactive HTML chart report using pyecharts."""
        alerts = self._alert_table.get_alerts()
        if not alerts:
            QMessageBox.information(self, "导出", "当前没有告警可导出。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 pyecharts 图表报告", "charts.html", "HTML 文件 (*.html)"
        )
        if not path:
            return

        try:
            self._generate_pyecharts_report(alerts, path)
            QMessageBox.information(self, "导出成功", f"已导出 pyecharts 图表报告到:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", f"pyecharts 图表生成出错:\n{exc}")

    def _generate_pyecharts_report(self, alerts: list[Alert], output_path: str) -> None:
        """Generate an interactive HTML report using pyecharts."""
        from pyecharts.charts import Bar, Line, Page, Pie
        from pyecharts import options as opts

        page = Page(page_title="网络攻击检测报告")
        page.add(self._pyecharts_pie(alerts))
        page.add(self._pyecharts_bar(alerts))
        page.add(self._pyecharts_line(alerts))
        page.render(output_path)

    def _pyecharts_pie(self, alerts: list[Alert]) -> Pie:
        from src.ui.stats_panel import CATEGORY_COLORS, StatsPanelModel

        cat_counts = StatsPanelModel.count_by_category(alerts)
        data_pairs = [(cat, cnt) for cat, cnt in cat_counts.items()]
        return (
            Pie(init_opts=opts.InitOpts(width="600px", height="400px"))
            .add(
                series_name="攻击类型",
                data_pair=data_pairs,
                radius=["30%", "60%"],
                label_opts=opts.LabelOpts(formatter="{b}: {c} ({d}%)"),
            )
            .set_global_opts(title_opts=opts.TitleOpts(title="攻击类型分布"))
            .set_colors([CATEGORY_COLORS.get(c, "#95A5A6") for c in cat_counts])
        )

    def _pyecharts_bar(self, alerts: list[Alert]) -> Bar:
        from src.ui.stats_panel import StatsPanelModel

        ip_counts = StatsPanelModel.count_by_src_ip(alerts)
        top10 = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ips = [ip for ip, _ in top10]
        counts = [c for _, c in top10]
        return (
            Bar(init_opts=opts.InitOpts(width="800px", height="400px"))
            .add_xaxis(ips)
            .add_yaxis("告警数量", counts)
            .reversal_axis()
            .set_series_opts(label_opts=opts.LabelOpts(position="right"))
            .set_global_opts(
                title_opts=opts.TitleOpts(title="Top 10 攻击源 IP"),
                xaxis_opts=opts.AxisOpts(name="告警数量"),
                yaxis_opts=opts.AxisOpts(name="源 IP"),
            )
        )

    def _pyecharts_line(self, alerts: list[Alert]) -> Line:
        from src.ui.stats_panel import StatsPanelModel

        total = StatsPanelModel.count_by_time(alerts)
        critical = StatsPanelModel.count_critical_by_time(alerts)
        high = StatsPanelModel.count_high_by_time(alerts)
        times = list(total.keys())

        return (
            Line(init_opts=opts.InitOpts(width="1000px", height="400px"))
            .add_xaxis(times)
            .add_yaxis("总告警", [total[t] for t in times], is_smooth=True)
            .add_yaxis("Critical", [critical[t] for t in times], is_smooth=True)
            .add_yaxis("High", [high[t] for t in times], is_smooth=True)
            .set_global_opts(
                title_opts=opts.TitleOpts(title="告警时间趋势 (最近 60 分钟)"),
                xaxis_opts=opts.AxisOpts(name="时间", axislabel_opts=opts.LabelOpts(rotate=45)),
                yaxis_opts=opts.AxisOpts(name="告警数量"),
            )
        )

    # ═══════════════════════════════════════════════════════════════════
    # Slot: other menu actions
    # ═══════════════════════════════════════════════════════════════════

    def _on_open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "打开 pcap 文件", "", "PCAP 文件 (*.pcap *.pcapng);;所有文件 (*)"
        )
        if path:
            self.pcap_file_requested.emit(path)

    def _on_reload_rules(self) -> None:
        self._rule_panel.refresh()
        self._event_bus.publish("rules_changed", None)

    def _on_toggle_traffic(self) -> None:
        visible = self._show_traffic_action.isChecked()
        self._traffic_table.setVisible(visible)

    def _on_toggle_stats(self) -> None:
        visible = self._show_stats_action.isChecked()
        self._stats_panel.setVisible(visible)

    def _on_clear_alerts(self) -> None:
        self._alert_table.clear()
        self._alert_count = 0

    def _on_about(self) -> None:
        QMessageBox.about(
            self,
            "关于",
            "<h3>Network Attack Detector</h3>"
            "<p>版本: 0.1.0</p>"
            "<p>基于流量分析与特征匹配的常见网络攻击检测系统</p>"
            "<p>技术栈: Python · PyQt6 · Scapy · matplotlib · pyecharts</p>",
        )

    # ═══════════════════════════════════════════════════════════════════
    # Periodic status bar refresh
    # ═══════════════════════════════════════════════════════════════════

    def _update_status_bar(self) -> None:
        import time

        # status indicator
        if self._capture_running:
            if self._capture_paused:
                self._status_indicator.setText("🟡 已暂停")
                self._status_indicator.setStyleSheet(
                    "QLabel { color: #F39C12; font-weight: bold; padding: 0 8px; }"
                )
            else:
                self._status_indicator.setText("🟢 运行中")
                self._status_indicator.setStyleSheet(
                    "QLabel { color: #27AE60; font-weight: bold; padding: 0 8px; }"
                )
        else:
            self._status_indicator.setText("⚫ 已停止")
            self._status_indicator.setStyleSheet(
                "QLabel { color: #7F8C8D; font-weight: bold; padding: 0 8px; }"
            )

        # packet count
        self._packet_count_label.setText(f"数据包: {self._packet_count}")
        self._alert_count_label.setText(f"告警: {self._alert_count}")

        # uptime
        if self._capture_running and self._start_time:
            elapsed = int(time.time() - self._start_time)
        elif self._capture_running:
            elapsed = 0
        else:
            elapsed = 0
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        self._uptime_label.setText(f"运行时间: {h:02d}:{m:02d}:{s:02d}")

    # ═══════════════════════════════════════════════════════════════════
    # Public API (for external launcher)
    # ═══════════════════════════════════════════════════════════════════

    def run(self) -> None:
        """Convenience entry point that starts the Qt event loop.

        For integration with the existing ``MainWindow.run()`` placeholder
        in the scaffold.  Prefer using :func:`QApplication.exec` when embedding
        the window in a larger application.
        """
        # If there is no running QApplication, create one.
        app = QApplication.instance()
        if app is None:
            app = QApplication([])
        self.show()
        app.exec()

    def set_interfaces(self, interfaces: list[str]) -> None:
        """Populate the interface combo box with available network interfaces.

        Called by the capture module after enumerating interfaces.
        """
        self._interface_combo.clear()
        if interfaces:
            for iface in interfaces:
                self._interface_combo.addItem(iface, iface)
        else:
            self._interface_combo.addItem("(无可用网卡)", "")
