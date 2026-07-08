from __future__ import annotations

from typing import Any

from src.core.constants import SUPPORTED_MATCH_TYPES
from src.core.exceptions import RuleError


class RuleValidator:
    def validate_signature_row(self, row: dict[str, str]) -> None:
        required = ["rule_id", "name", "category", "level", "protocol", "match_type", "pattern"]
        missing = [field for field in required if not row.get(field)]
        if missing:
            raise RuleError(f"Signature rule missing fields: {missing}")
        if row["match_type"].strip().lower() not in SUPPORTED_MATCH_TYPES:
            raise RuleError(f"Unsupported match type: {row['match_type']}")

    def validate_behavior_row(self, row: dict[str, Any]) -> None:
        required = ["rule_id", "name", "category", "level", "event_type", "window_seconds", "threshold"]
        missing = [field for field in required if field not in row]
        if missing:
            raise RuleError(f"Behavior rule missing fields: {missing}")
        if int(row["window_seconds"]) <= 0:
            raise RuleError("window_seconds must be positive.")
        if int(row["threshold"]) <= 0:
            raise RuleError("threshold must be positive.")

