import pytest

from src.core.exceptions import RuleError
from src.rules.rule_validator import RuleValidator


def make_row(**overrides):
    row = {
        "rule_id": "SIG-TEST-001",
        "name": "test rule",
        "category": "SQL Injection",
        "level": "High",
        "protocol": "HTTP",
        "match_type": "content",
        "pattern": "union select",
        "target_fields": "http.query;payload_text",
        "nocase": "true",
        "enabled": "true",
        "description": "test description",
        "suggestion": "test suggestion",
    }
    row.update(overrides)
    return row


def test_valid_signature_row_passes():
    RuleValidator().validate_signature_row(make_row(), line_number=2)


def test_duplicate_rule_id_contains_id_and_line():
    validator = RuleValidator()
    validator.validate_signature_row(make_row(), line_number=2)

    with pytest.raises(RuleError, match=r"rule_id=SIG-TEST-001, line=3"):
        validator.validate_signature_row(make_row(), line_number=3)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("category", "Invalid Category"),
        ("level", "Severe"),
        ("protocol", "SMTP"),
    ],
)
def test_invalid_enum_is_rejected(field, value):
    with pytest.raises(RuleError, match=rf"invalid {field}"):
        RuleValidator().validate_signature_row(
            make_row(**{field: value}), line_number=8
        )


def test_empty_content_pattern_is_rejected():
    with pytest.raises(RuleError, match="content pattern must not be empty"):
        RuleValidator().validate_signature_row(make_row(pattern="   "), line_number=4)


def test_invalid_regex_is_rejected():
    with pytest.raises(RuleError, match="invalid regex pattern"):
        RuleValidator().validate_signature_row(
            make_row(match_type="regex", pattern="("), line_number=5
        )


def test_unknown_target_field_is_rejected():
    with pytest.raises(RuleError, match="unsupported target_fields"):
        RuleValidator().validate_signature_row(
            make_row(target_fields="http.query;http.invalid"), line_number=6
        )


@pytest.mark.parametrize("field", ["nocase", "enabled"])
@pytest.mark.parametrize("value", ["1", "yes", "on", ""])
def test_boolean_fields_are_strict(field, value):
    with pytest.raises(RuleError, match=rf"{field} must be exactly"):
        RuleValidator().validate_signature_row(
            make_row(**{field: value}), line_number=7
        )


def test_missing_csv_header_is_rejected():
    headers = set(make_row()) - {"suggestion"}
    with pytest.raises(RuleError, match="CSV header missing columns"):
        RuleValidator().validate_signature_headers(headers)

