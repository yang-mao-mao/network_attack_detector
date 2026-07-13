from __future__ import annotations

from collections.abc import Iterable

from src.core.exceptions import RuleError
from src.core.models import BehaviorRule, SignatureRule


Rule = SignatureRule | BehaviorRule


class RuleManager:
    """Manage signature and behavior rules in memory.

    The manager does not persist changes. Callers that need persistence should
    explicitly synchronize the resulting lists with a repository or rule file.
    """

    def __init__(
        self,
        signature_rules: list[SignatureRule] | None = None,
        behavior_rules: list[BehaviorRule] | None = None,
    ) -> None:
        # 复制传入列表，避免外部增删列表时绕过管理器。
        self.signature_rules = list(signature_rules or [])
        self.behavior_rules = list(behavior_rules or [])
        self._validate_all_rule_ids(self.list_rules())

    def list_rules(self) -> list[Rule]:
        """Return a snapshot containing signature rules followed by behavior rules."""
        return [*self.signature_rules, *self.behavior_rules]

    def get_rule(self, rule_id: str) -> Rule | None:
        """Return the rule with ``rule_id`` or ``None`` when it does not exist."""
        normalized_id = self._normalize_rule_id(rule_id)
        for rule in self.list_rules():
            if rule.rule_id == normalized_id:
                return rule
        return None

    def add_rule(self, rule: Rule) -> bool:
        """Add one rule; duplicate IDs are rejected."""
        self._validate_rule(rule)
        if self.get_rule(rule.rule_id) is not None:
            raise RuleError(f"Rule ID already exists: {rule.rule_id}")

        self._list_for_rule(rule).append(rule)
        return True

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID and report whether a rule was found."""
        normalized_id = self._normalize_rule_id(rule_id)
        for rules in (self.signature_rules, self.behavior_rules):
            for index, rule in enumerate(rules):
                if rule.rule_id == normalized_id:
                    del rules[index]
                    return True
        return False

    def update_rule(self, rule: Rule) -> bool:
        """Replace an existing rule while preserving its list position."""
        self._validate_rule(rule)
        for rules in (self.signature_rules, self.behavior_rules):
            for index, current in enumerate(rules):
                if current.rule_id != rule.rule_id:
                    continue
                if type(current) is not type(rule):
                    raise RuleError(
                        f"Rule type cannot change during update: {rule.rule_id}"
                    )
                rules[index] = rule
                return True
        return False

    def replace_signature_rules(self, rules: Iterable[SignatureRule]) -> None:
        """Atomically replace all signature rules after complete validation."""
        replacement = list(rules)
        for rule in replacement:
            if not isinstance(rule, SignatureRule):
                raise RuleError(
                    "replace_signature_rules accepts SignatureRule objects only"
                )
            self._validate_rule(rule)

        # 特征规则内部及其与现有行为规则之间都不允许 ID 冲突。
        self._validate_all_rule_ids([*replacement, *self.behavior_rules])
        self.signature_rules = replacement

    def enable_rule(self, rule_id: str) -> bool:
        return self._set_enabled(rule_id, True)

    def disable_rule(self, rule_id: str) -> bool:
        return self._set_enabled(rule_id, False)

    def _set_enabled(self, rule_id: str, enabled: bool) -> bool:
        rule = self.get_rule(rule_id)
        if rule is None:
            return False
        rule.enabled = enabled
        return True

    def _list_for_rule(self, rule: Rule) -> list[SignatureRule] | list[BehaviorRule]:
        if isinstance(rule, SignatureRule):
            return self.signature_rules
        if isinstance(rule, BehaviorRule):
            return self.behavior_rules
        raise RuleError(
            f"Unsupported rule object: {type(rule).__name__}; "
            "expected SignatureRule or BehaviorRule"
        )

    @classmethod
    def _validate_rule(cls, rule: object) -> None:
        if not isinstance(rule, (SignatureRule, BehaviorRule)):
            raise RuleError(
                f"Unsupported rule object: {type(rule).__name__}; "
                "expected SignatureRule or BehaviorRule"
            )
        cls._normalize_rule_id(rule.rule_id)

    @classmethod
    def _validate_all_rule_ids(cls, rules: Iterable[Rule]) -> None:
        seen: set[str] = set()
        for rule in rules:
            cls._validate_rule(rule)
            rule_id = cls._normalize_rule_id(rule.rule_id)
            if rule_id in seen:
                raise RuleError(f"Duplicate rule ID: {rule_id}")
            seen.add(rule_id)

    @staticmethod
    def _normalize_rule_id(rule_id: str) -> str:
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise RuleError("rule_id must be a non-empty string")
        if rule_id != rule_id.strip():
            raise RuleError(f"rule_id must not contain surrounding whitespace: {rule_id!r}")
        return rule_id
