from __future__ import annotations

from src.core.models import BehaviorRule, SignatureRule


class RuleRepository:
    def __init__(self) -> None:
        self.signature_rules: list[SignatureRule] = []
        self.behavior_rules: list[BehaviorRule] = []

    def replace_all(
        self,
        signature_rules: list[SignatureRule],
        behavior_rules: list[BehaviorRule],
    ) -> None:
        self.signature_rules = signature_rules
        self.behavior_rules = behavior_rules

