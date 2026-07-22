from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path
from threading import RLock
from typing import Any

from src.core.exceptions import RuleError
from src.core.models import DetectionResult, PacketInfo, SignatureRule
from src.detection.signature_engine import SignatureEngine
from src.rules.rule_loader import RuleLoader
from src.rules.rule_manager import RuleManager
from src.rules.rule_validator import RuleValidator


class SignatureDetectionService:
    """Coordinate signature rule loading, management, and packet detection.

    This class is intentionally independent of PyQt and packet-capture code.
    Members A and E can therefore use the same API from the main program or
    GUI, while member B only needs to supply standardized ``PacketInfo``
    objects.
    """

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self.loader = RuleLoader()
        self.manager = RuleManager()
        self.engine = SignatureEngine(self.manager.signature_rules)
        self.rules_path: Path | None = None
        self._lock = RLock()

        if rules_path is not None:
            self.load_rules(rules_path)

    def load_rules(self, path: str | Path) -> list[SignatureRule]:
        """Load a rule file and atomically make it the active rule set."""
        rule_path = Path(path)
        with self._lock:
            rules = self.loader.load_signature_rules(rule_path)
            self._replace_active_rules(rules)
            self.rules_path = rule_path
            return list(self.manager.signature_rules)

    def reload_rules(self, path: str | Path | None = None) -> list[SignatureRule]:
        """Reload a file, retaining the active rules if validation fails."""
        rule_path = Path(path) if path is not None else self.rules_path
        if rule_path is None:
            raise RuleError("No signature rule file has been selected for reload")

        with self._lock:
            # RuleLoader only updates its cache after a complete successful read.
            rules = self.loader.reload_signature_rules(rule_path)
            self._replace_active_rules(rules)
            self.rules_path = rule_path
            return list(self.manager.signature_rules)

    def list_rules(self) -> list[SignatureRule]:
        with self._lock:
            return list(self.manager.signature_rules)

    def get_rule(self, rule_id: str) -> SignatureRule | None:
        with self._lock:
            rule = self.manager.get_rule(rule_id)
            return rule if isinstance(rule, SignatureRule) else None

    def add_rule(self, rule: SignatureRule) -> bool:
        with self._lock:
            self._validate_signature_rules([rule])
            changed = self.manager.add_rule(rule)
            if changed:
                self._rules_changed()
            return changed

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            changed = self.manager.remove_rule(rule_id)
            if changed:
                self._rules_changed()
            return changed

    def update_rule(self, rule: SignatureRule) -> bool:
        with self._lock:
            self._validate_signature_rules([rule])
            changed = self.manager.update_rule(rule)
            if changed:
                self._rules_changed()
            return changed

    def replace_rules(self, rules: Iterable[SignatureRule]) -> list[SignatureRule]:
        """Atomically replace active in-memory rules after full validation."""
        replacement = list(rules)
        with self._lock:
            self._validate_signature_rules(replacement)
            self.manager.replace_signature_rules(replacement)
            self._rules_changed()
            return list(self.manager.signature_rules)

    def enable_rule(self, rule_id: str) -> bool:
        with self._lock:
            changed = self.manager.enable_rule(rule_id)
            if changed:
                self._sync_loader_cache()
            return changed

    def disable_rule(self, rule_id: str) -> bool:
        with self._lock:
            changed = self.manager.disable_rule(rule_id)
            if changed:
                self._sync_loader_cache()
            return changed

    def detect(self, packet: PacketInfo) -> DetectionResult:
        """Detect one packet and return the public ``DetectionResult`` model."""
        if not isinstance(packet, PacketInfo):
            raise TypeError("packet must be a PacketInfo object")

        with self._lock:
            started = time.perf_counter()
            alerts = self.engine.detect(packet)
            return DetectionResult(
                packet_id=packet.packet_id,
                matched=bool(alerts),
                alerts=alerts,
                engine_name="SignatureEngine",
                cost_ms=(time.perf_counter() - started) * 1000,
            )

    def _replace_active_rules(self, rules: list[SignatureRule]) -> None:
        self.manager.replace_signature_rules(rules)
        self.engine = SignatureEngine(self.manager.signature_rules)
        self._sync_loader_cache()

    def _rules_changed(self) -> None:
        # Structural changes require a fresh regex and packet/rule dedup cache.
        self.engine = SignatureEngine(self.manager.signature_rules)
        self._sync_loader_cache()

    def _sync_loader_cache(self) -> None:
        self.loader.signature_rules = list(self.manager.signature_rules)

    @classmethod
    def _validate_signature_rules(cls, rules: list[SignatureRule]) -> None:
        validator = RuleValidator()
        for line_number, rule in enumerate(rules, start=2):
            if not isinstance(rule, SignatureRule):
                raise RuleError(
                    "SignatureDetectionService accepts SignatureRule objects only"
                )
            validator.validate_signature_row(
                cls._rule_to_validation_row(rule),
                line_number=line_number,
            )

    @staticmethod
    def _rule_to_validation_row(rule: SignatureRule) -> dict[str, str]:
        if not isinstance(rule.target_fields, list) or not all(
            isinstance(field, str) for field in rule.target_fields
        ):
            raise RuleError(
                f"Signature rule error [rule_id={rule.rule_id}, line=<memory>]: "
                "target_fields must be a list of strings"
            )
        if not isinstance(rule.nocase, bool) or not isinstance(rule.enabled, bool):
            raise RuleError(
                f"Signature rule error [rule_id={rule.rule_id}, line=<memory>]: "
                "nocase and enabled must be boolean values"
            )
        if not isinstance(rule.pattern, str):
            raise RuleError(
                f"Signature rule error [rule_id={rule.rule_id}, line=<memory>]: "
                "pattern must be a string"
            )

        def enum_value(value: Any) -> str:
            return str(getattr(value, "value", value))

        return {
            "rule_id": str(rule.rule_id),
            "name": str(rule.name),
            "category": enum_value(rule.category),
            "level": enum_value(rule.level),
            "protocol": enum_value(rule.protocol),
            "match_type": str(rule.match_type),
            "pattern": rule.pattern,
            "target_fields": ";".join(rule.target_fields),
            "nocase": "true" if rule.nocase else "false",
            "enabled": "true" if rule.enabled else "false",
            "description": str(rule.description),
            "suggestion": str(rule.suggestion),
        }
