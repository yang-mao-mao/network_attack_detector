from pathlib import Path

import pytest

from src.core.exceptions import RuleError
from src.rules.rule_loader import RuleLoader


def test_load_rules():
    root = Path(__file__).resolve().parents[1]
    loader = RuleLoader()
    signature_rules = loader.load_signature_rules(root / "data/rules/signature_rules.csv")
    behavior_rules = loader.load_behavior_rules(root / "data/rules/behavior_rules.json")
    assert signature_rules
    assert behavior_rules


def _signature_csv(rows: list[str]) -> str:
    header = (
        "rule_id,name,category,level,protocol,match_type,pattern,target_fields,"
        "nocase,enabled,description,suggestion"
    )
    return "\n".join([header, *rows]) + "\n"


def _valid_row(rule_id: str = "SIG-TEST-001") -> str:
    return (
        f"{rule_id}, Test Rule ,SQL Injection,High,HTTP,content, union select ,"
        "http.query; payload_text ,true,false, description , suggestion "
    )


def test_load_signature_rules_strips_fields_and_converts_booleans(tmp_path):
    path = tmp_path / "rules.csv"
    path.write_text(_signature_csv([_valid_row()]), encoding="utf-8")

    rule = RuleLoader().load_signature_rules(path)[0]

    assert rule.rule_id == "SIG-TEST-001"
    assert rule.name == "Test Rule"
    assert rule.pattern == "union select"
    assert rule.target_fields == ["http.query", "payload_text"]
    assert rule.nocase is True
    assert rule.enabled is False


def test_reload_replaces_cache(tmp_path):
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    first.write_text(_signature_csv([_valid_row("SIG-TEST-001")]), encoding="utf-8")
    second.write_text(_signature_csv([_valid_row("SIG-TEST-002")]), encoding="utf-8")
    loader = RuleLoader()

    loader.load_signature_rules(first)
    result = loader.reload_signature_rules(second)

    assert [rule.rule_id for rule in result] == ["SIG-TEST-002"]
    assert loader.signature_rules == result


def test_failed_reload_preserves_previous_cache(tmp_path):
    valid = tmp_path / "valid.csv"
    invalid = tmp_path / "invalid.csv"
    valid.write_text(_signature_csv([_valid_row()]), encoding="utf-8")
    invalid.write_text(_signature_csv([]), encoding="utf-8")
    loader = RuleLoader()
    previous = loader.load_signature_rules(valid)

    with pytest.raises(RuleError):
        loader.reload_signature_rules(invalid)

    assert loader.signature_rules == previous


@pytest.mark.parametrize("kind", ["missing", "empty", "encoding"])
def test_file_errors_are_rule_errors(tmp_path, kind):
    path = tmp_path / "rules.csv"
    if kind == "empty":
        path.write_text("", encoding="utf-8")
    elif kind == "encoding":
        path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(RuleError):
        RuleLoader().load_signature_rules(path)


def test_duplicate_id_reports_current_csv_line(tmp_path):
    path = tmp_path / "rules.csv"
    path.write_text(_signature_csv([_valid_row(), _valid_row()]), encoding="utf-8")

    with pytest.raises(RuleError, match=r"rule_id=SIG-TEST-001, line=3"):
        RuleLoader().load_signature_rules(path)


def test_strict_boolean_rejects_yes(tmp_path):
    path = tmp_path / "rules.csv"
    path.write_text(
        _signature_csv([_valid_row().replace(",true,false,", ",yes,false,")]),
        encoding="utf-8",
    )

    with pytest.raises(RuleError, match="nocase must be exactly"):
        RuleLoader().load_signature_rules(path)

