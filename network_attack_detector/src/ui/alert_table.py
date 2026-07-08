from __future__ import annotations

from src.core.models import Alert


class AlertTableModel:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)

