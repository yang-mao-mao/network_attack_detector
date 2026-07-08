from __future__ import annotations

import sqlite3
from pathlib import Path


class Database:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    category TEXT NOT NULL,
                    level TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    rule_id TEXT,
                    rule_name TEXT,
                    evidence TEXT,
                    description TEXT,
                    suggestion TEXT,
                    packet_id TEXT,
                    extra_json TEXT
                );

                CREATE TABLE IF NOT EXISTS packets (
                    packet_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    payload_preview TEXT,
                    raw_summary TEXT
                );
                """
            )

