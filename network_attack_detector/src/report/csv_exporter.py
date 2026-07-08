from __future__ import annotations

import csv
from pathlib import Path

from src.core.models import Alert


class CsvExporter:
    def export(self, alerts: list[Alert], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["time", "level", "category", "src_ip", "dst_ip", "rule_id", "evidence"])
            for alert in alerts:
                writer.writerow(
                    [
                        alert.timestamp,
                        alert.level.value,
                        alert.category.value,
                        alert.src_ip,
                        alert.dst_ip,
                        alert.rule_id,
                        alert.evidence,
                    ]
                )

