from pathlib import Path

from src.core.models import AlertLevel, AttackCategory, HttpInfo, PacketInfo, Protocol, SignatureRule
from src.detection.signature_engine import SignatureEngine
from src.parser.packet_parser import PacketParser
from src.rules.rule_loader import RuleLoader


def test_signature_engine_detects_sql_injection():
    root = Path(__file__).resolve().parents[1]
    rules = RuleLoader().load_signature_rules(root / "data/rules/signature_rules.csv")
    packet = PacketParser().parse_http_bytes(
        b"GET /?q=1%20union%20select%20password HTTP/1.1\r\nHost: demo\r\n\r\n"
    )
    alerts = SignatureEngine(rules).detect(packet)
    assert any(alert.category.value == "SQL Injection" for alert in alerts)


def _rule(rule_id, match_type, pattern, target_fields):
    return SignatureRule(
        rule_id=rule_id,
        name=rule_id,
        category=AttackCategory.XSS,
        level=AlertLevel.HIGH,
        protocol=Protocol.HTTP,
        match_type=match_type,
        pattern=pattern,
        target_fields=target_fields,
    )


def _packet(packet_id="PKT-TEST"):
    return PacketInfo(
        packet_id=packet_id,
        timestamp=1.0,
        protocol=Protocol.HTTP,
        payload_text="fallback marker",
        http=HttpInfo(url="/safe", query="needle", body="x" * 700),
    )


def test_multi_field_match_records_matched_field():
    engine = SignatureEngine([_rule("SIG-MULTI", "content", "needle", ["http.url", "http.query"])])

    alert = engine.detect(_packet())[0]

    assert alert.evidence == "needle"
    assert alert.extra["matched_field"] == "http.query"
    assert alert.extra["match_type"] == "content"


def test_empty_target_fields_default_to_payload_text():
    alert = SignatureEngine(
        [_rule("SIG-DEFAULT", "content", "fallback marker", [])]
    ).detect(_packet())[0]

    assert alert.extra["matched_field"] == "payload_text"


def test_invalid_regex_does_not_block_valid_rule():
    engine = SignatureEngine(
        [
            _rule("SIG-BAD", "regex", "(", ["payload_text"]),
            _rule("SIG-GOOD", "content", "fallback", ["payload_text"]),
        ]
    )

    assert [alert.rule_id for alert in engine.detect(_packet())] == ["SIG-GOOD"]


def test_regex_is_cached_and_long_evidence_is_truncated():
    engine = SignatureEngine([_rule("SIG-LONG", "regex", "x+", ["http.body"])])

    alert = engine.detect(_packet())[0]

    assert len(engine._regex_cache) == 1
    assert len(alert.evidence) == 515
    assert alert.evidence.endswith("...")


def test_duplicate_rule_and_repeated_packet_do_not_duplicate_alert():
    rule = _rule("SIG-DEDUP", "content", "needle", ["http.query"])
    engine = SignatureEngine([rule, rule])
    packet = _packet()

    assert len(engine.detect(packet)) == 1
    assert engine.detect(packet) == []


