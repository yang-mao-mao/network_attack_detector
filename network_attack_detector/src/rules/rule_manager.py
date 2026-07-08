from __future__ import annotations

from src.core.models import BehaviorRule, SignatureRule


class RuleManager:
    def __init__(
        self,
        signature_rules: list[SignatureRule] | None = None,
        behavior_rules: list[BehaviorRule] | None = None,
    ) -> None:
        self.signature_rules = signature_rules or []
        self.behavior_rules = behavior_rules or []

    def enable_rule(self, rule_id: str) -> bool:
        return self._set_enabled(rule_id, True)

    def disable_rule(self, rule_id: str) -> bool:
        return self._set_enabled(rule_id, False)

    def _set_enabled(self, rule_id: str, enabled: bool) -> bool:
        for rule in [*self.signature_rules, *self.behavior_rules]:
            if rule.rule_id == rule_id:
                rule.enabled = enabled
                return True
        return False

