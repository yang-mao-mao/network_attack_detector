from __future__ import annotations

from collections import Counter

from src.core.models import Alert


class StatsPanelModel:
    @staticmethod
    def count_by_category(alerts: list[Alert]) -> dict[str, int]:
        return dict(Counter(alert.category.value for alert in alerts))

