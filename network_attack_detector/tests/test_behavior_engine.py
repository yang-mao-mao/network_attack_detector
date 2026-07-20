from src.core.models import AlertLevel, AttackCategory, BehaviorRule, PacketInfo, Protocol
from src.detection.behavior_engine import BehaviorEngine


def test_behavior_engine_detects_port_scan():
    rule = BehaviorRule(
        rule_id="BEH-T",
        name="test",
        category=AttackCategory.PORT_SCAN,
        level=AlertLevel.MEDIUM,
        event_type="distinct_dst_ports",
        window_seconds=60,
        threshold=3,
        group_by=["src_ip", "dst_ip"],
        condition={"protocol": "TCP"},
    )
    engine = BehaviorEngine([rule])
    alerts = []
    for port in [21, 22, 23]:
        packet = PacketInfo(
            packet_id=f"p{port}",
            timestamp=1.0 + port,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port=port,
            protocol=Protocol.TCP,
        )
        alerts.extend(engine.update_and_detect(packet))
    assert alerts

