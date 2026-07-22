from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QWidget

from core.models import Alert, AlertLevel, PacketInfo

# =============================================================================
# Helpers
# =============================================================================


def _val(field):
    """Safely extract the string value from an enum or plain-string field."""
    return getattr(field, "value", field)


# =============================================================================
# HtmlReporter — comprehensive overall report in HTML format
# =============================================================================


class HtmlReporter:
    """Export a comprehensive overall report as a standalone HTML page.

    The report combines **attack detection data** (alerts) and **network
    traffic data** (packets) collected by
    :class:`~ui.statistic.statistic.StatisticWindow`, presenting:

    * Summary cards (total alerts, level breakdown, top categories, …)
    * Full attack-detail table
    * Source-IP ranking table
    """

    # ── Public entry point ─────────────────────────────────────────────────

    def export(
        self,
        alerts: list[Alert],
        output_path: str | Path,
        packets: list[PacketInfo] | None = None,
    ) -> None:
        """Generate the HTML file.

        Parameters
        ----------
        alerts:
            Attack alerts collected by detection engines or the
            statistics panel.
        output_path:
            Destination ``.html`` file path.  Parent directories are
            created automatically.
        packets:
            Optional captured packet list used to build the IP-ranking
            section.  When omitted the ranking section is hidden.
        """
        if packets is None:
            packets = []

        html = self._build_html(alerts, packets)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")

    # ── HTML assembly ──────────────────────────────────────────────────────

    def _build_html(
        self,
        alerts: list[Alert],
        packets: list[PacketInfo],
    ) -> str:
        return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Attack Detection — Overall Report</title>
{self._css()}
</head>
<body>

<div class="container">

{self._header(alerts, packets)}

{self._summary_section(alerts, packets)}

{self._attack_table_section(alerts)}

{self._ip_ranking_section(packets)}

{self._footer()}

</div>

</body>
</html>"""

    # ── CSS (dark theme — matching the PyQt6 application) ──────────────────

    @staticmethod
    def _css() -> str:
        return """<style>
:root {
    --bg-0: #1e1e1e;
    --bg-1: #2d2d2d;
    --bg-2: #3c3c3c;
    --border: #3e3e3e;
    --text: #d4d4d4;
    --text-muted: #888888;
    --accent: #007acc;
    --red: #ff4444;
    --yellow: #ffdd44;
    --green: #4ec9b0;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    background-color: var(--bg-0);
    color: var(--text);
    line-height: 1.6;
}

.container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 24px;
}

/* ── Header ─────────────────────────────────── */
.header {
    text-align: center;
    padding: 32px 0 24px;
    border-bottom: 2px solid var(--accent);
    margin-bottom: 28px;
}
.header h1 {
    font-size: 28px;
    color: #ffffff;
    font-weight: 700;
}
.header .subtitle {
    font-size: 14px;
    color: var(--text-muted);
    margin-top: 6px;
}

/* ── Summary cards ───────────────────────────── */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 32px;
}
.card {
    background-color: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
    text-align: center;
}
.card .label {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 6px;
}
.card .value {
    font-size: 32px;
    font-weight: 700;
}
.card.critical .value { color: var(--red); }
.card.high     .value { color: #ff6b6b; }
.card.medium   .value { color: var(--yellow); }
.card.low      .value { color: var(--green); }
.card.info     .value { color: var(--accent); }

/* ── Section titles ──────────────────────────── */
.section-title {
    font-size: 18px;
    font-weight: 700;
    color: #ffffff;
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
    margin: 32px 0 14px;
}

/* ── Tables ──────────────────────────────────── */
table {
    width: 100%;
    border-collapse: collapse;
    background-color: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    font-size: 13px;
}
thead th {
    background-color: #252525;
    color: var(--text);
    font-weight: 700;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 2px solid var(--accent);
    white-space: nowrap;
}
tbody td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
tbody tr:hover {
    background-color: var(--bg-2);
}

.level-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 700;
    color: #ffffff;
}
.lvl-Critical  { background-color: var(--red); }
.lvl-High      { background-color: #e05d5d; }
.lvl-Medium    { background-color: #c9a800; color: #1e1e1e; }
.lvl-Low       { background-color: var(--green); color: #1e1e1e; }

/* ── Footer ──────────────────────────────────── */
.footer {
    text-align: center;
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-muted);
}
</style>"""

    # ── Header block ───────────────────────────────────────────────────────

    @staticmethod
    def _header(alerts: list[Alert], packets: list[PacketInfo]) -> str:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""<div class="header">
<h1>🛡 Network Attack Detection — Overall Report</h1>
<div class="subtitle">
    Generated: {escape(now_str)} &nbsp;|&nbsp;
    {len(alerts)} alert(s) &nbsp;|&nbsp;
    {len(packets)} packet(s)
</div>
</div>"""

    # ── Summary cards ──────────────────────────────────────────────────────

    @staticmethod
    def _summary_section(
        alerts: list[Alert],
        packets: list[PacketInfo],
    ) -> str:
        level_counts = Counter(a.level for a in alerts)
        category_counts = Counter(a.category for a in alerts)

        total_alerts = len(alerts)
        critical = level_counts.get(AlertLevel.CRITICAL, 0)
        high = level_counts.get(AlertLevel.HIGH, 0)
        medium = level_counts.get(AlertLevel.MEDIUM, 0)
        low = level_counts.get(AlertLevel.LOW, 0)

        unique_src_ips = len({a.src_ip for a in alerts if a.src_ip})

        top_category = ""
        top_cat_count = 0
        if category_counts:
            top_cat, top_cat_count = category_counts.most_common(1)[0]
            top_category = f"{_val(top_cat)} ({top_cat_count})"

        cards = f"""
<div class="summary-grid">
    <div class="card info">
        <div class="label">Total Alerts</div>
        <div class="value">{total_alerts}</div>
    </div>
    <div class="card critical">
        <div class="label">Critical</div>
        <div class="value">{critical}</div>
    </div>
    <div class="card high">
        <div class="label">High</div>
        <div class="value">{high}</div>
    </div>
    <div class="card medium">
        <div class="label">Medium</div>
        <div class="value">{medium}</div>
    </div>
    <div class="card low">
        <div class="label">Low</div>
        <div class="value">{low}</div>
    </div>
    <div class="card info">
        <div class="label">Unique Source IPs</div>
        <div class="value">{unique_src_ips}</div>
    </div>
    <div class="card info">
        <div class="label">Packets Captured</div>
        <div class="value">{len(packets)}</div>
    </div>
</div>"""

        if top_category:
            cards += f"""<div class="summary-grid">
    <div class="card info" style="grid-column: 1 / -1;">
        <div class="label">Top Attack Category</div>
        <div class="value" style="font-size: 22px;">{escape(top_category)}</div>
    </div>
</div>"""

        return cards

    # ── Attack detail table ────────────────────────────────────────────────

    @staticmethod
    def _attack_table_section(alerts: list[Alert]) -> str:
        if not alerts:
            return """<h2 class="section-title">Attack Details</h2>
<p style="color: #888; padding: 12px 0;">No attack alerts recorded.</p>"""

        rows = "\n".join(
            "<tr>"
            f"<td>{escape(datetime.fromtimestamp(a.timestamp).strftime('%Y-%m-%d %H:%M:%S') if a.timestamp else '—')}</td>"
            f'<td><span class="level-badge lvl-{escape(_val(a.level))}">{escape(_val(a.level))}</span></td>'
            f"<td>{escape(_val(a.category))}</td>"
            f"<td>{escape(a.src_ip or '—')}</td>"
            f"<td>{escape(str(a.src_port) if a.src_port else '—')}</td>"
            f"<td>{escape(a.dst_ip or '—')}</td>"
            f"<td>{escape(str(a.dst_port) if a.dst_port else '—')}</td>"
            f"<td>{escape(_val(a.protocol))}</td>"
            f"<td>{escape(a.rule_id)}</td>"
            f"<td>{escape(a.rule_name)}</td>"
            f"<td>{escape(a.evidence[:120])}{'…' if len(a.evidence) > 120 else ''}</td>"
            "</tr>"
            for a in alerts
        )

        return f"""<h2 class="section-title">Attack Details</h2>
<table>
<thead><tr>
    <th>Time</th><th>Level</th><th>Category</th>
    <th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th>
    <th>Protocol</th><th>Rule ID</th><th>Rule Name</th><th>Evidence</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>"""

    # ── IP ranking table ───────────────────────────────────────────────────

    @staticmethod
    def _ip_ranking_section(packets: list[PacketInfo]) -> str:
        if not packets:
            return ""

        # Count source IP occurrences
        ip_counts: dict[str, int] = {}
        for pkt in packets:
            if pkt.src_ip:
                ip_counts[pkt.src_ip] = ip_counts.get(pkt.src_ip, 0) + 1

        sorted_ips = sorted(ip_counts.items(), key=lambda kv: -kv[1])

        rows = "\n".join(
            f"<tr><td>{rank}</td><td>{escape(ip)}</td><td>{count}</td></tr>"
            for rank, (ip, count) in enumerate(sorted_ips, 1)
        )

        return f"""<h2 class="section-title">Source IP Ranking</h2>
<table>
<thead><tr><th>Rank</th><th>Source IP</th><th>Packet Count</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>"""

    # ── Footer ─────────────────────────────────────────────────────────────

    @staticmethod
    def _footer() -> str:
        return """<div class="footer">
Network Attack Detector &mdash; Report generated automatically.
</div>"""


# =============================================================================
# Standalone helper — called from the Statistics UI
# =============================================================================


def generate_overall_report(
    alerts: list[Alert],
    packets: list[PacketInfo],
    parent: QWidget | None = None,
) -> None:
    """Open a save-file dialog and export the comprehensive HTML report.

    This function is wired to the **GEN HTML REPORT** menu action in
    :class:`~ui.statistic.statistic.StatisticWindow`.  It bundles both
    alert and packet data into a single, styled HTML page.

    Parameters
    ----------
    alerts:
        Current attack alerts (from ``StatisticWindow._attacks``).
    packets:
        Current captured packets (from ``StatisticWindow._packets``).
    parent:
        Parent widget for the native file dialog and message boxes.
    """
    if not alerts and not packets:
        QMessageBox.information(
            parent,
            "No Data",
            "No alerts or packets have been collected yet.\n\n"
            "Wait for data collection or enable mock-data generation.",
        )
        return

    default_name = (
        f"overall_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "Save Overall Report — HTML",
        default_name,
        "HTML Files (*.html *.htm);;All Files (*)",
    )
    if not path:
        return  # user cancelled

    try:
        reporter = HtmlReporter()
        reporter.export(alerts, path, packets)
        QMessageBox.information(
            parent,
            "Export Successful",
            f"Overall report saved to:\n\n{path}",
        )
    except Exception as exc:
        QMessageBox.critical(
            parent,
            "Export Failed",
            f"Could not write the HTML report:\n\n{exc}",
        )