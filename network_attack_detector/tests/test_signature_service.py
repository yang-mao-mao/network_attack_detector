from dataclasses import replace
from pathlib import Path

import pytest

from src.core.exceptions import RuleError
from src.core.models import (
    AlertLevel,
    AttackCategory,
    PacketInfo,
    Protocol,
    SignatureRule,
)
from src.detection.signature_service import SignatureDetectionService
from src.parser.packet_parser import PacketParser


def make_rule(
    rule_id: str = "SIG-TEST-001",
    pattern: str = "needle",
    enabled: bool = True,
) -> SignatureRule:
    return SignatureRule(
        rule_id=rule_id,
        name=rule_id,
        category=AttackCategory.XSS,
        level=AlertLevel.HIGH,
        protocol=Protocol.HTTP,
        match_type="content",
        pattern=pattern,
        target_fields=["payload_text"],
        nocase=True,
        enabled=enabled,
        description="test rule",
        suggestion="test suggestion",
    )


def packet(packet_id: str, payload: str = "contains needle") -> PacketInfo:
    return PacketInfo(
        packet_id=packet_id,
        timestamp=1.0,
        protocol=Protocol.HTTP,
        payload_text=payload,
    )


def test_load_rules_and_return_detection_result():
    root = Path(__file__).resolve().parents[1]
    service = SignatureDetectionService(root / "data/rules/signature_rules.csv")
    parsed = PacketParser().parse_http_bytes(
        b"GET /?q=union%20select%20password HTTP/1.1\r\nHost: demo\r\n\r\n"
    )

    result = service.detect(parsed)

    assert len(service.list_rules()) == 45
    assert result.matched is True
    assert result.engine_name == "SignatureEngine"
    assert result.packet_id == parsed.packet_id
    assert any(alert.category == AttackCategory.SQL_INJECTION for alert in result.alerts)


def test_in_memory_crud_rebuilds_active_engine():
    service = SignatureDetectionService()
    rule = make_rule()

    assert service.add_rule(rule)
    assert service.detect(packet("PKT-1")).matched

    updated = replace(rule, pattern="changed")
    assert service.update_rule(updated)
    assert not service.detect(packet("PKT-2")).matched
    assert service.detect(packet("PKT-3", "contains changed")).matched

    assert service.remove_rule(rule.rule_id)
    assert not service.detect(packet("PKT-4", "contains changed")).matched


def test_enable_and_disable_take_effect_without_file_reload():
    service = SignatureDetectionService()
    service.add_rule(make_rule())

    assert service.disable_rule("SIG-TEST-001")
    assert not service.detect(packet("PKT-OFF")).matched
    assert service.enable_rule("SIG-TEST-001")
    assert service.detect(packet("PKT-ON")).matched


def test_invalid_in_memory_rule_is_rejected_without_changing_active_rules():
    service = SignatureDetectionService()
    service.add_rule(make_rule())
    invalid = make_rule("SIG-TEST-002", pattern="")

    with pytest.raises(RuleError, match="content pattern must not be empty"):
        service.add_rule(invalid)

    assert [rule.rule_id for rule in service.list_rules()] == ["SIG-TEST-001"]


def test_duplicate_replace_is_atomic():
    service = SignatureDetectionService()
    original = make_rule("SIG-ORIGINAL")
    service.add_rule(original)
    duplicate = make_rule("SIG-DUPLICATE")

    with pytest.raises(RuleError, match="duplicate rule_id"):
        service.replace_rules([duplicate, replace(duplicate)])

    assert service.list_rules() == [original]


def test_failed_reload_preserves_active_rules(tmp_path):
    valid_path = tmp_path / "valid.csv"
    invalid_path = tmp_path / "invalid.csv"
    valid_path.write_text(
        "rule_id,name,category,level,protocol,match_type,pattern,target_fields,"
        "nocase,enabled,description,suggestion\n"
        "SIG-TEST-001,test,XSS,High,HTTP,content,needle,payload_text,"
        "true,true,test,test\n",
        encoding="utf-8",
    )
    invalid_path.write_text("", encoding="utf-8")
    service = SignatureDetectionService(valid_path)

    with pytest.raises(RuleError):
        service.reload_rules(invalid_path)

    assert service.rules_path == valid_path
    assert service.detect(packet("PKT-AFTER-FAILED-RELOAD")).matched


def test_reload_without_selected_path_is_rejected():
    with pytest.raises(RuleError, match="No signature rule file"):
        SignatureDetectionService().reload_rules()


def test_detect_requires_packet_info():
    with pytest.raises(TypeError, match="PacketInfo"):
        SignatureDetectionService().detect(object())
