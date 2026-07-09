"""User interface package.

Provides PyQt6-based GUI components for the network attack detection system:

- MainWindow: Main application window with menus, toolbar, and central layout
- AlertTableView / AlertTableModel: Real-time alert display with color coding
- TrafficTableView / TrafficTableModel: Real-time packet traffic display
- RulePanel: Rule management (view, enable/disable, add, delete, search)
- StatsPanel: Statistics charts (attack distribution, Top IPs, timeline)
"""

from __future__ import annotations

from src.ui.alert_table import AlertTableModel, AlertTableView
from src.ui.main_window import MainWindow
from src.ui.rule_panel import RulePanel
from src.ui.stats_panel import StatsPanel
from src.ui.traffic_table import TrafficTableModel, TrafficTableView

__all__ = [
    "AlertTableModel",
    "AlertTableView",
    "MainWindow",
    "RulePanel",
    "StatsPanel",
    "TrafficTableModel",
    "TrafficTableView",
]
