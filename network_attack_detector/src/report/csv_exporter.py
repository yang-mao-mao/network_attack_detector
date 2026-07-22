from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QWidget

from core.models import Alert

# =============================================================================
# Helpers
# =============================================================================


def _val(field):
    """Safely extract the string value from an enum or plain-string field."""
    return getattr(field, "value", field)


# =============================================================================
# CsvExporter — attack detection report in CSV format
# =============================================================================


class CsvExporter:
    """Export attack detection alerts to a CSV file.

    The exported CSV includes all alert fields collected by
    ``ui/statistic/statistic.py``, formatted for direct analysis
    in spreadsheet applications.
    """

    _HEADER: list[str] = [
        "alert_id",
        "timestamp",
        "level",
        "category",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "rule_id",
        "rule_name",
        "evidence",
        "description",
        "suggestion",
    ]

    def export(self, alerts: list[Alert], output_path: str | Path) -> None:
        """Write *alerts* to *output_path* as a UTF-8 CSV file.

        Parameters
        ----------
        alerts:
            Attack alerts collected by the detection engines or the
            statistics panel.
        output_path:
            Destination file path.  Parent directories are created
            automatically when they don't exist.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(self._HEADER)

            for alert in alerts:
                writer.writerow([
                    alert.alert_id,
                    datetime.fromtimestamp(alert.timestamp).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    _val(alert.level),
                    _val(alert.category),
                    alert.src_ip or "",
                    alert.src_port if alert.src_port is not None else "",
                    alert.dst_ip or "",
                    alert.dst_port if alert.dst_port is not None else "",
                    _val(alert.protocol),
                    alert.rule_id,
                    alert.rule_name,
                    alert.evidence,
                    alert.description,
                    alert.suggestion,
                ])


# =============================================================================
# Standalone helper — called from the Statistics UI
# =============================================================================


def generate_attack_report(
    alerts: list[Alert],
    parent: QWidget | None = None,
) -> None:
    """Open a save-file dialog and export the attack detection report as CSV.

    This function is wired to the **GEN CSV REPORT** menu action in
    :class:`~ui.statistic.statistic.StatisticWindow`.  It prompts the
    user for a destination path, then delegates to :class:`CsvExporter`.

    Parameters
    ----------
    alerts:
        The current list of detected attack alerts (typically sourced
        from ``StatisticWindow._attacks``).
    parent:
        Parent widget for the native file dialog and message boxes.
    """
    if not alerts:
        QMessageBox.information(
            parent,
            "No Data",
            "No attack alerts have been collected yet.\n\n"
            "Wait for detections to fire or enable mock-data generation.",
        )
        return

    default_name = (
        f"attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "Save Attack Detection Report — CSV",
        default_name,
        "CSV Files (*.csv);;All Files (*)",
    )
    if not path:
        return  # user cancelled the dialog

    try:
        exporter = CsvExporter()
        exporter.export(alerts, path)
        QMessageBox.information(
            parent,
            "Export Successful",
            f"Attack detection report saved to:\n\n{path}",
        )
    except Exception as exc:
        QMessageBox.critical(
            parent,
            "Export Failed",
            f"Could not write the CSV report:\n\n{exc}",
        )
