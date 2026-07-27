"""User interface package."""

from src.ui.alert_table import AlertTableModel
from src.ui.rule_panel import RulePanel
from src.ui.stats_panel import StatsPanelModel
from src.ui.traffic_table import TrafficTableModel

__all__ = [
    "AlertTableModel",
    "MainWindow",
    "RulePanel",
    "StatsPanelModel",
    "TrafficTableModel",
]


def __getattr__(name: str):
    if name == "MainWindow":
        from src.ui.main_window import MainWindow

        return MainWindow
    raise AttributeError(f"module 'src.ui' has no attribute {name!r}")
