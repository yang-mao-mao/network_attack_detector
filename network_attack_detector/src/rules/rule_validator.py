from __future__ import annotations

import re
from collections.abc import Collection
from typing import Any

from src.core.constants import SUPPORTED_MATCH_TYPES
from src.core.exceptions import RuleError
from src.core.models import AlertLevel, AttackCategory, Protocol


class RuleValidator:
    """Validate external rule records before they become model objects.

    A validator instance tracks signature rule IDs and CSV data-row numbers.  One
    instance should therefore be used for one loading session.  Call
    ``reset_signature_state`` before reusing it to reload a complete rule file.
    """

    # 特征规则 CSV 必须包含的完整表头。
    SIGNATURE_HEADERS = frozenset(
        {
            "rule_id",
            "name",
            "category",
            "level",
            "protocol",
            "match_type",
            "pattern",
            "target_fields",
            "nocase",
            "enabled",
            "description",
            "suggestion",
        }
    )
    # 每条规则中不可缺失或留空的核心字段。
    REQUIRED_SIGNATURE_FIELDS = frozenset(
        {
            "rule_id",
            "name",
            "category",
            "level",
            "protocol",
            "match_type",
            "pattern",
        }
    )
    # 检测引擎当前支持读取的目标字段，避免无效字段静默失效。
    TARGET_FIELD_WHITELIST = frozenset(
        {
            "payload_text",
            "raw_summary",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "http.method",
            "http.host",
            "http.url",
            "http.path",
            "http.query",
            "http.user_agent",
            "http.status_code",
            "http.headers",
            "http.body",
        }
    )
    # CSV 布尔字段采用严格格式，不接受 1、yes、on 等模糊写法。
    STRICT_BOOLEAN_VALUES = frozenset({"true", "false"})

    def __init__(self) -> None:
        # 分别维护特征规则和行为规则的校验状态及行号。
        self.reset_signature_state()
        self._behavior_row_number = 1

    def reset_signature_state(self) -> None:
        """Start a new signature CSV validation session."""
        self._seen_signature_ids: set[str] = set()
        # CSV header is line 1; the first record is line 2.
        self._signature_row_number = 1
        self._signature_headers_checked = False

    def validate_signature_headers(
        self,
        fieldnames: Collection[str | None] | None,
        line_number: int = 1,
    ) -> None:
        """Validate that a signature CSV contains every defined column."""
        # 显式接口也可用于空 CSV；逐行校验时会在第一条记录自动调用。
        try:
            headers = {str(name).strip() for name in (fieldnames or []) if name is not None}
            missing = sorted(self.SIGNATURE_HEADERS - headers)
            if missing:
                raise ValueError(f"CSV header missing columns: {missing}")
            if None in (fieldnames or []):
                raise ValueError("CSV header contains an empty column name")
        except RuleError:
            raise
        except (TypeError, ValueError) as exc:
            raise self._signature_error("<header>", line_number, str(exc)) from exc

    def validate_signature_row(
        self,
        row: dict[str, str],
        line_number: int | None = None,
    ) -> None:
        """Validate one signature CSV row and raise a contextual RuleError."""
        # 未显式传入行号时，按 CSV 首条数据位于第 2 行自动计数。
        if line_number is None:
            self._signature_row_number += 1
            line_number = self._signature_row_number
        else:
            self._signature_row_number = line_number

        rule_id = self._rule_id_for_error(row)
        try:
            if not isinstance(row, dict):
                raise TypeError("signature rule row must be a mapping")

            # 首条数据到来时检查完整表头，保持与现有 RuleLoader 兼容。
            if not self._signature_headers_checked:
                self.validate_signature_headers(row.keys())
                self._signature_headers_checked = True

            # csv.DictReader stores surplus columns under the None key.
            if None in row:
                raise ValueError("row has more values than the CSV header")

            missing = sorted(
                field
                for field in self.REQUIRED_SIGNATURE_FIELDS
                if not self._non_empty(row.get(field))
            )
            if missing:
                raise ValueError(f"missing required fields: {missing}")

            rule_id = row["rule_id"].strip()
            if rule_id in self._seen_signature_ids:
                raise ValueError(f"duplicate rule_id: {rule_id}")

            # 在构造模型前完成枚举转换所需的合法性检查。
            self._validate_enum(row["category"], AttackCategory, "category")
            self._validate_enum(row["level"], AlertLevel, "level")
            self._validate_enum(row["protocol"], Protocol, "protocol")

            match_type = row["match_type"].strip().lower()
            if match_type not in SUPPORTED_MATCH_TYPES:
                raise ValueError(f"unsupported match_type: {row['match_type']!r}")

            # content 必须非空；regex 还必须能被 Python 正则引擎编译。
            pattern = row["pattern"]
            if match_type == "content" and not pattern.strip():
                raise ValueError("content pattern must not be empty")
            if match_type == "regex":
                if not pattern.strip():
                    raise ValueError("regex pattern must not be empty")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f"invalid regex pattern: {exc}") from exc

            self._validate_target_fields(row.get("target_fields", ""))
            self._validate_strict_boolean(row.get("nocase"), "nocase")
            self._validate_strict_boolean(row.get("enabled"), "enabled")

            # Add only after every validation succeeds so a corrected row with
            # the same ID can still be retried by a caller.
            self._seen_signature_ids.add(rule_id)
        except RuleError:
            raise
        # 将所有外部格式错误统一包装为带规则 ID 和行号的 RuleError。
        except (KeyError, TypeError, ValueError) as exc:
            raise self._signature_error(rule_id, line_number, str(exc)) from exc

    def validate_behavior_row(
        self,
        row: dict[str, Any],
        line_number: int | None = None,
    ) -> None:
        """Validate a behavior rule with the same contextual error contract."""
        if line_number is None:
            self._behavior_row_number += 1
            line_number = self._behavior_row_number

        # 行为规则沿用相同的上下文化异常格式。
        rule_id = self._rule_id_for_error(row)
        try:
            required = {
                "rule_id",
                "name",
                "category",
                "level",
                "event_type",
                "window_seconds",
                "threshold",
            }
            missing = sorted(field for field in required if not self._non_empty(row.get(field)))
            if missing:
                raise ValueError(f"missing required fields: {missing}")

            rule_id = str(row["rule_id"]).strip()
            self._validate_enum(row["category"], AttackCategory, "category")
            self._validate_enum(row["level"], AlertLevel, "level")
            if int(row["window_seconds"]) <= 0:
                raise ValueError("window_seconds must be positive")
            if int(row["threshold"]) <= 0:
                raise ValueError("threshold must be positive")
            if "enabled" in row and not isinstance(row["enabled"], bool):
                raise ValueError("enabled must be a JSON boolean")
        except RuleError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise RuleError(
                f"Behavior rule error [rule_id={rule_id}, row={line_number}]: {exc}"
            ) from exc

    @classmethod
    def _validate_target_fields(cls, value: Any) -> None:
        if value is None or not isinstance(value, str):
            raise ValueError("target_fields must be a semicolon-separated string")
        fields = [field.strip() for field in value.split(";") if field.strip()]
        invalid = sorted(set(fields) - cls.TARGET_FIELD_WHITELIST)
        if invalid:
            raise ValueError(f"unsupported target_fields: {invalid}")

    @classmethod
    def _validate_strict_boolean(cls, value: Any, field_name: str) -> None:
        if not isinstance(value, str) or value.strip().lower() not in cls.STRICT_BOOLEAN_VALUES:
            raise ValueError(f"{field_name} must be exactly 'true' or 'false'")

    @staticmethod
    def _validate_enum(value: Any, enum_type: type, field_name: str) -> None:
        try:
            enum_type(str(value).strip())
        except (TypeError, ValueError) as exc:
            allowed = [item.value for item in enum_type]
            raise ValueError(
                f"invalid {field_name}: {value!r}; allowed values: {allowed}"
            ) from exc

    @staticmethod
    def _non_empty(value: Any) -> bool:
        return value is not None and bool(str(value).strip())

    @staticmethod
    def _rule_id_for_error(row: Any) -> str:
        if isinstance(row, dict):
            value = row.get("rule_id")
            if value is not None and str(value).strip():
                return str(value).strip()
        return "<unknown>"

    @staticmethod
    def _signature_error(rule_id: str, line_number: int, message: str) -> RuleError:
        return RuleError(
            f"Signature rule error [rule_id={rule_id}, line={line_number}]: {message}"
        )
