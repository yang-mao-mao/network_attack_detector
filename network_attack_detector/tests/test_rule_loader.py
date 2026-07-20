from pathlib import Path

from src.rules.rule_loader import RuleLoader


def test_load_rules():
    root = Path(__file__).resolve().parents[1]
    loader = RuleLoader()
    signature_rules = loader.load_signature_rules(root / "data/rules/signature_rules.csv")
    behavior_rules = loader.load_behavior_rules(root / "data/rules/behavior_rules.json")
    assert signature_rules
    assert behavior_rules

