from __future__ import annotations

from ..core.models import BehaviorRule, SignatureRule

#静态识别--特征规则     动态识别--行为规则
Rule = SignatureRule | BehaviorRule


class RuleRepository:
    """In-memory repository for loaded detection rules.

    RuleLoader is responsible for reading CSV/JSON files.
    RuleRepository is only responsible for keeping loaded rule objects available
    during the current program run.
    """

    def __init__(
        self,
        signature_rules: list[SignatureRule] | None = None,
        behavior_rules: list[BehaviorRule] | None = None,
    ) -> None:
        self.signature_rules: list[SignatureRule] = []
        self.behavior_rules: list[BehaviorRule] = []
        self.replace_all(signature_rules or [], behavior_rules or [])

    def replace_all(
        self,
        signature_rules: list[SignatureRule],
        behavior_rules: list[BehaviorRule],
    ) -> None:
        """Replace all rules currently stored in memory."""
        self._ensure_unique_rule_ids([*signature_rules, *behavior_rules])
        self.signature_rules = list(signature_rules)
        self.behavior_rules = list(behavior_rules)

    def list_signature_rules(self, enabled_only: bool = False) -> list[SignatureRule]:
        """Return signature rules, optionally filtering out disabled rules."""
        if enabled_only:
            return [rule for rule in self.signature_rules if rule.enabled]
        return list(self.signature_rules)

    def list_behavior_rules(self, enabled_only: bool = False) -> list[BehaviorRule]:
        """Return behavior rules, optionally filtering out disabled rules."""
        if enabled_only:
            return [rule for rule in self.behavior_rules if rule.enabled]
        return list(self.behavior_rules)

    def list_all(self, enabled_only: bool = False) -> list[Rule]:
        """Return all rules in a single list."""
        return [
            *self.list_signature_rules(enabled_only=enabled_only),
            *self.list_behavior_rules(enabled_only=enabled_only),
        ]

    def find_signature_by_id(self, rule_id: str) -> SignatureRule | None:
        """Find a signature rule by rule_id."""
        for rule in self.signature_rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def find_behavior_by_id(self, rule_id: str) -> BehaviorRule | None:
        """Find a behavior rule by rule_id."""
        for rule in self.behavior_rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def find_by_id(self, rule_id: str) -> Rule | None:
        """Find any rule by rule_id."""
        return self.find_signature_by_id(rule_id) or self.find_behavior_by_id(rule_id)

    def add_signature_rule(self, rule: SignatureRule) -> None:
        """Add a new signature rule.

        Raises ValueError if a rule with the same rule_id already exists.
        """
        self._raise_if_rule_exists(rule.rule_id)
        self.signature_rules.append(rule)

    def add_behavior_rule(self, rule: BehaviorRule) -> None:
        """Add a new behavior rule.

        Raises ValueError if a rule with the same rule_id already exists.
        """
        self._raise_if_rule_exists(rule.rule_id)
        self.behavior_rules.append(rule)

    def save_signature_rule(self, rule: SignatureRule) -> None:
        """Insert or replace a signature rule."""
        index = self._find_rule_index(self.signature_rules, rule.rule_id)
        if index is None:
            self._raise_if_rule_exists(rule.rule_id)
            self.signature_rules.append(rule)
            return
        self.signature_rules[index] = rule

    def save_behavior_rule(self, rule: BehaviorRule) -> None:
        """Insert or replace a behavior rule."""
        index = self._find_rule_index(self.behavior_rules, rule.rule_id)
        if index is None:
            self._raise_if_rule_exists(rule.rule_id)
            self.behavior_rules.append(rule)
            return
        self.behavior_rules[index] = rule

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule by rule_id.

        Returns True when the rule exists, otherwise False.
        """
        rule = self.find_by_id(rule_id)
        if rule is None:
            return False
        rule.enabled = enabled
        return True

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by rule_id."""
        return self.set_enabled(rule_id, True)

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by rule_id."""
        return self.set_enabled(rule_id, False)

    def delete(self, rule_id: str) -> bool:
        """Delete a rule by rule_id.

        Returns True when a rule is deleted, otherwise False.
        """
        signature_index = self._find_rule_index(self.signature_rules, rule_id)
        if signature_index is not None:
            del self.signature_rules[signature_index]
            return True

        behavior_index = self._find_rule_index(self.behavior_rules, rule_id)
        if behavior_index is not None:
            del self.behavior_rules[behavior_index]
            return True

        return False

    def clear(self) -> None:
        """Remove all rules from the repository."""
        self.signature_rules.clear()
        self.behavior_rules.clear()

    def count_signature_rules(self, enabled_only: bool = False) -> int:
        """Count signature rules."""
        return len(self.list_signature_rules(enabled_only=enabled_only))

    def count_behavior_rules(self, enabled_only: bool = False) -> int:
        """Count behavior rules."""
        return len(self.list_behavior_rules(enabled_only=enabled_only))

    def count_all(self, enabled_only: bool = False) -> int:
        """Count all rules."""
        return len(self.list_all(enabled_only=enabled_only))

    def _raise_if_rule_exists(self, rule_id: str) -> None:
        if self.find_by_id(rule_id) is not None:
            raise ValueError(f"Rule already exists: {rule_id}")

    @staticmethod
    def _find_rule_index(rules: list[Rule], rule_id: str) -> int | None:
        for index, rule in enumerate(rules):
            if rule.rule_id == rule_id:
                return index
        return None

    @staticmethod
    def _ensure_unique_rule_ids(rules: list[Rule]) -> None:
        seen: set[str] = set()
        for rule in rules:
            if rule.rule_id in seen:
                raise ValueError(f"Duplicate rule_id: {rule.rule_id}")
            seen.add(rule.rule_id)
