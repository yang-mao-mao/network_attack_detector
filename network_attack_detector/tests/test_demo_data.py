from __future__ import annotations

from src.demo_data import build_demo_dataset, filter_result_by_rule_prefix


def test_demo_dataset_covers_signature_and_behavior_rules() -> None:
    dataset = build_demo_dataset()

    assert len(dataset.packets) == 34
    assert len(dataset.alerts) == 5

    rule_ids = {alert.rule_id for alert in dataset.alerts}
    assert {
        "SIG-SQLI-001",
        "SIG-XSS-001",
        "SIG-CMDI-003",
        "BEH-2001",
        "BEH-2002",
    }.issubset(rule_ids)


def test_demo_result_filter_keeps_requested_engine_alerts() -> None:
    dataset = build_demo_dataset()
    matched_results = [result for result in dataset.results if result.alerts]

    signature_results = [
        filter_result_by_rule_prefix(result, "SIG-", "SignatureEngine")
        for result in matched_results
    ]
    behavior_results = [
        filter_result_by_rule_prefix(result, "BEH-", "BehaviorEngine")
        for result in matched_results
    ]

    assert sum(1 for result in signature_results if result is not None) == 3
    assert sum(1 for result in behavior_results if result is not None) == 2
