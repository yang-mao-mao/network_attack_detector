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
from src.core.exceptions import RuleError
from src.rules.rule_validator import RuleValidator


class RuleLoader:
    def __init__(self) -> None:
        self.validator = RuleValidator()
        self.signature_rules: list[SignatureRule] = []

    def load_signature_rules(self, path: str | Path) -> list[SignatureRule]:
        """加载并校验特征规则，成功后更新当前内存规则列表。"""
        rules = self._read_signature_rules(path)
        self.signature_rules = rules
        return rules

    def reload_signature_rules(self, path: str | Path) -> list[SignatureRule]:
        """重新读取完整规则文件，失败时保留上一次成功加载的规则。"""
        rules = self._read_signature_rules(path)
        self.signature_rules = rules
        return rules

    def _read_signature_rules(self, path: str | Path) -> list[SignatureRule]:
        rule_path = Path(path)
        if not rule_path.exists():
            raise RuleError(f"Signature rule file does not exist: {rule_path}")
        if not rule_path.is_file():
            raise RuleError(f"Signature rule path is not a file: {rule_path}")

        # 每次完整加载都重新统计行号和重复 ID，避免 reload 误判旧规则。
        self.validator.reset_signature_state()
        rules: list[SignatureRule] = []
        try:
            with rule_path.open("r", encoding="utf-8-sig", errors="strict", newline="") as file:
                reader = csv.DictReader(file, strict=True)
                if reader.fieldnames is None:
                    raise RuleError(f"Signature rule file is empty: {rule_path}")

                # 表头和普通字段都去除首尾空白，再交由统一校验器处理。
                normalized_headers = [
                    header.strip() if header is not None else None
                    for header in reader.fieldnames
                ]
                if len(normalized_headers) != len(set(normalized_headers)):
                    raise RuleError(
                        "Signature rule error [rule_id=<header>, line=1]: "
                        "CSV header contains duplicate columns"
                    )
                reader.fieldnames = normalized_headers
                self.validator.validate_signature_headers(normalized_headers)

                for line_number, raw_row in enumerate(reader, start=2):
                    row = self._strip_row(raw_row)
                    self.validator.validate_signature_row(row, line_number=line_number)
                    try:
                        rules.append(self._to_signature_rule(row))
                    except RuleError:
                        raise
                    except (KeyError, TypeError, ValueError) as exc:
                        rule_id = row.get("rule_id") or "<unknown>"
                        raise RuleError(
                            "Signature rule conversion error "
                            f"[rule_id={rule_id}, line={line_number}]: {exc}"
                        ) from exc
        except RuleError:
            raise
        except UnicodeError as exc:
            raise RuleError(
                f"Signature rule file encoding error: {rule_path}; expected UTF-8: {exc}"
            ) from exc
        except csv.Error as exc:
            line_number = max(getattr(reader, "line_num", 1), 1)
            raise RuleError(
                "Signature rule CSV format error "
                f"[rule_id=<unknown>, line={line_number}]: {exc}"
            ) from exc
        except OSError as exc:
            raise RuleError(f"Unable to read signature rule file {rule_path}: {exc}") from exc

        if not rules:
            raise RuleError(f"Signature rule file contains no data rows: {rule_path}")
        return rules

    def _to_signature_rule(self, row: dict[str, str]) -> SignatureRule:
        return SignatureRule(
            rule_id=row["rule_id"],
            name=row["name"],
            category=AttackCategory(row["category"]),
            level=AlertLevel(row["level"]),
            protocol=Protocol(row["protocol"]),
            match_type=row["match_type"].lower(),
            pattern=row["pattern"],
            target_fields=self._split_fields(row.get("target_fields", "")),
            nocase=self._as_bool(row.get("nocase"), "nocase"),
            enabled=self._as_bool(row.get("enabled"), "enabled"),
            description=row.get("description", ""),
            suggestion=row.get("suggestion", ""),
        )

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
    def _as_bool(value: Any, field_name: str = "value") -> bool:
        """严格转换布尔字段，只接受 CSV 中的 true 或 false。"""
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be exactly 'true' or 'false'")
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        raise ValueError(f"{field_name} must be exactly 'true' or 'false'")

    @staticmethod
    def _strip_row(row: dict[str | None, Any]) -> dict[str, str]:
        """去除字段名和字符串值的首尾空白，同时保留多余列标记。"""
        normalized: dict[Any, Any] = {}
        for key, value in row.items():
            clean_key = key.strip() if isinstance(key, str) else key
            clean_value = value.strip() if isinstance(value, str) else value
            normalized[clean_key] = clean_value
        return normalized

