from __future__ import annotations

import csv
from datetime import datetime
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


def generate_attack_report(alerts: list[Alert], parent=None) -> None:
    from PyQt6.QtWidgets import QFileDialog, QMessageBox

    if not alerts:
        QMessageBox.information(parent, "No Data", "No attack alerts have been collected yet.")
        return

    default_name = f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "Save Attack Detection Report - CSV",
        default_name,
        "CSV Files (*.csv);;All Files (*)",
    )
    if not path:
        return

    try:
        CsvExporter().export(alerts, path)
        QMessageBox.information(parent, "Export Successful", f"Report saved to:\n\n{path}")
    except Exception as exc:
        QMessageBox.critical(parent, "Export Failed", str(exc))
