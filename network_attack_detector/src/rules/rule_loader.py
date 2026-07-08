from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from src.core.models import (
    AlertLevel,
    AttackCategory,
    BehaviorRule,
    Protocol,
    SignatureRule,
)
from src.rules.rule_validator import RuleValidator


class RuleLoader:
    def __init__(self) -> None:
        self.validator = RuleValidator()

    def load_signature_rules(self, path: str | Path) -> list[SignatureRule]:
        rules: list[SignatureRule] = []
        with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
            for row in csv.DictReader(file):
                self.validator.validate_signature_row(row)
                rules.append(
                    SignatureRule(
                        rule_id=row["rule_id"].strip(),
                        name=row["name"].strip(),
                        category=AttackCategory(row["category"].strip()),
                        level=AlertLevel(row["level"].strip()),
                        protocol=Protocol(row["protocol"].strip()),
                        match_type=row["match_type"].strip().lower(),
                        pattern=row["pattern"],
                        target_fields=self._split_fields(row.get("target_fields", "")),
                        nocase=self._as_bool(row.get("nocase", "true")),
                        enabled=self._as_bool(row.get("enabled", "true")),
                        description=row.get("description", ""),
                        suggestion=row.get("suggestion", ""),
                    )
                )
        return rules

    def load_behavior_rules(self, path: str | Path) -> list[BehaviorRule]:
        content = json.loads(Path(path).read_text(encoding="utf-8"))
        rules: list[BehaviorRule] = []
        for row in content:
            self.validator.validate_behavior_row(row)
            rules.append(
                BehaviorRule(
                    rule_id=row["rule_id"],
                    name=row["name"],
                    category=AttackCategory(row["category"]),
                    level=AlertLevel(row["level"]),
                    event_type=row["event_type"],
                    window_seconds=int(row["window_seconds"]),
                    threshold=int(row["threshold"]),
                    group_by=list(row.get("group_by", [])),
                    condition=dict(row.get("condition", {})),
                    enabled=bool(row.get("enabled", True)),
                    description=row.get("description", ""),
                    suggestion=row.get("suggestion", ""),
                )
            )
        return rules

    @staticmethod
    def _split_fields(value: str) -> list[str]:
        return [item.strip() for item in value.split(";") if item.strip()]

    @staticmethod
    def _as_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}

