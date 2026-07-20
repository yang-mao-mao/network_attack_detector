from __future__ import annotations

from html import escape
from pathlib import Path

from src.core.models import Alert


class HtmlReporter:
    def export(self, alerts: list[Alert], output_path: str | Path) -> None:
        rows = "\n".join(
            "<tr>"
            f"<td>{escape(alert.level.value)}</td>"
            f"<td>{escape(alert.category.value)}</td>"
            f"<td>{escape(str(alert.src_ip))}</td>"
            f"<td>{escape(str(alert.dst_ip))}</td>"
            f"<td>{escape(alert.rule_id)}</td>"
            f"<td>{escape(alert.evidence)}</td>"
            "</tr>"
            for alert in alerts
        )
        html = f"""<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Detection Report</title></head>
<body>
<h1>Network Attack Detection Report</h1>
<table border="1" cellspacing="0" cellpadding="6">
<thead><tr><th>Level</th><th>Category</th><th>Source</th><th>Destination</th><th>Rule</th><th>Evidence</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")

