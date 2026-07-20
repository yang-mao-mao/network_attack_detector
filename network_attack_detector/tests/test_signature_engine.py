from pathlib import Path

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

