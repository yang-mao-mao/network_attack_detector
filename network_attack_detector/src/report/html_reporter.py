from __future__ import annotations

from html import escape
from pathlib import Path

from src.core.models import Alert, PacketInfo


class HtmlReporter:
    def export(
        self,
        alerts: list[Alert],
        output_path: str | Path,
        packets: list[PacketInfo] | None = None,
    ) -> None:
        packets = packets or []
        alert_rows = "\n".join(
            "<tr>"
            f"<td>{escape(str(getattr(alert.level, 'value', alert.level)))}</td>"
            f"<td>{escape(str(getattr(alert.category, 'value', alert.category)))}</td>"
            f"<td>{escape(str(alert.src_ip))}</td>"
            f"<td>{escape(str(alert.dst_ip))}</td>"
            f"<td>{escape(alert.rule_id)}</td>"
            f"<td>{escape(alert.evidence)}</td>"
            "</tr>"
            for alert in alerts
        )
        ip_counts: dict[str, int] = {}
        for packet in packets:
            if packet.src_ip:
                ip_counts[packet.src_ip] = ip_counts.get(packet.src_ip, 0) + 1
        packet_rows = "\n".join(
            f"<tr><td>{rank}</td><td>{escape(ip)}</td><td>{count}</td></tr>"
            for rank, (ip, count) in enumerate(
                sorted(ip_counts.items(), key=lambda item: -item[1]),
                start=1,
            )
        )
        html = f"""<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Detection Report</title></head>
<body>
<h1>Network Attack Detection Report</h1>
<p>Total alerts: {len(alerts)} | Total packets: {len(packets)}</p>
<h2>Alerts</h2>
<table border="1" cellspacing="0" cellpadding="6">
<thead><tr><th>Level</th><th>Category</th><th>Source</th><th>Destination</th><th>Rule</th><th>Evidence</th></tr></thead>
<tbody>
{alert_rows}
</tbody>
</table>
<h2>Source IP Ranking</h2>
<table border="1" cellspacing="0" cellpadding="6">
<thead><tr><th>Rank</th><th>Source IP</th><th>Packet Count</th></tr></thead>
<tbody>
{packet_rows}
</tbody>
</table>
</body>
</html>
"""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")


def generate_overall_report(
    alerts: list[Alert],
    packets: list[PacketInfo],
    parent=None,
) -> None:
    from PyQt6.QtWidgets import QFileDialog, QMessageBox

    if not alerts and not packets:
        QMessageBox.information(parent, "No Data", "No alerts or packets have been collected yet.")
        return

    path, _ = QFileDialog.getSaveFileName(
        parent,
        "Save Overall Report - HTML",
        "overall_report.html",
        "HTML Files (*.html *.htm);;All Files (*)",
    )
    if not path:
        return

    try:
        HtmlReporter().export(alerts, path, packets)
        QMessageBox.information(parent, "Export Successful", f"Report saved to:\n\n{path}")
    except Exception as exc:
        QMessageBox.critical(parent, "Export Failed", str(exc))
