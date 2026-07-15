from dataclasses import replace

import pytest

from src.core.exceptions import RuleError
from src.core.models import AlertLevel, AttackCategory, BehaviorRule, Protocol, SignatureRule
from src.rules.rule_manager import RuleManager


def signature_rule(rule_id="SIG-TEST-001", enabled=True):
    return SignatureRule(
        rule_id=rule_id,
        name=rule_id,
        category=AttackCategory.XSS,
        level=AlertLevel.HIGH,
        protocol=Protocol.HTTP,
        match_type="content",
        pattern="<script",
        target_fields=["payload_text"],
        enabled=enabled,
    )


def behavior_rule(rule_id="BEH-TEST-001"):
    return BehaviorRule(
        rule_id=rule_id,
        name=rule_id,
        category=AttackCategory.PORT_SCAN,
        level=AlertLevel.MEDIUM,
        event_type="distinct_dst_ports",
        window_seconds=60,
        threshold=10,
    )


def test_list_returns_snapshot_and_get_finds_both_rule_types():
    signature = signature_rule()
    behavior = behavior_rule()
    manager = RuleManager([signature], [behavior])

    snapshot = manager.list_rules()
    snapshot.clear()

    assert len(manager.list_rules()) == 2
    assert manager.get_rule(signature.rule_id) is signature
    assert manager.get_rule(behavior.rule_id) is behavior
    assert manager.get_rule("missing") is None


def test_add_update_and_remove_rule():
    manager = RuleManager()
    rule = signature_rule()

    assert manager.add_rule(rule)
    updated = replace(rule, name="updated")
    assert manager.update_rule(updated)
    assert manager.get_rule(rule.rule_id).name == "updated"
    assert manager.remove_rule(rule.rule_id)
    assert not manager.remove_rule(rule.rule_id)


def test_enable_and_disable_rule():
    manager = RuleManager([signature_rule()])

    assert manager.disable_rule("SIG-TEST-001")
    assert manager.get_rule("SIG-TEST-001").enabled is False
    assert manager.enable_rule("SIG-TEST-001")
    assert manager.get_rule("SIG-TEST-001").enabled is True
    assert not manager.enable_rule("missing")


def test_duplicate_rule_id_is_rejected_across_types():
    manager = RuleManager([signature_rule()])

    with pytest.raises(RuleError, match="already exists"):
        manager.add_rule(behavior_rule("SIG-TEST-001"))


def test_update_cannot_change_rule_type():
    manager = RuleManager([signature_rule()])

    with pytest.raises(RuleError, match="type cannot change"):
        manager.update_rule(behavior_rule("SIG-TEST-001"))


def test_replace_signature_rules_is_atomic():
    original = signature_rule("SIG-OLD")
    manager = RuleManager([original], [behavior_rule()])
    first = signature_rule("SIG-NEW")
    duplicate = replace(first)

    with pytest.raises(RuleError, match="Duplicate rule ID"):
        manager.replace_signature_rules([first, duplicate])

    assert manager.signature_rules == [original]


def test_replace_signature_rules_succeeds():
    manager = RuleManager([signature_rule("SIG-OLD")])
    replacement = [signature_rule("SIG-NEW-001"), signature_rule("SIG-NEW-002")]

    manager.replace_signature_rules(replacement)

    assert manager.signature_rules == replacement
