from __future__ import annotations

import json

from src.core.models import Alert
from src.storage.database import Database


class AlertRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def save(self, alert: Alert) -> None:
        with self.database.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, category, level, src_ip, dst_ip,
                    src_port, dst_port, protocol, rule_id, rule_name, evidence,
                    description, suggestion, packet_id, extra_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp,
                    alert.category.value,
                    alert.level.value,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.src_port,
                    alert.dst_port,
                    alert.protocol.value,
                    alert.rule_id,
                    alert.rule_name,
                    alert.evidence,
                    alert.description,
                    alert.suggestion,
                    alert.packet_id,
                    json.dumps(alert.extra, ensure_ascii=False),
                ),
            )

