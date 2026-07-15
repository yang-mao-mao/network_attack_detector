from src.core.models import (
    AlertLevel, AttackCategory, BehaviorRule, PacketInfo, Protocol, HttpInfo
)
from src.detection.behavior_engine import BehaviorEngine


def test_behavior_engine_detects_port_scan():
    rule = BehaviorRule(
        rule_id="BEH-T1",
        name="test_port_scan",
        category=AttackCategory.PORT_SCAN,
        level=AlertLevel.MEDIUM,
        event_type="distinct_dst_ports",
        window_seconds=60,
        threshold=3,
        group_by=["src_ip", "dst_ip"],
        condition={"protocol": "TCP"},
        enabled=True,
        description="Test port scan",
        suggestion="Check scanner"
    )
    engine = BehaviorEngine([rule])
    src, dst = "10.0.0.1", "10.0.0.2"
    alerts = []
    # 前2个包不触发
    for port in [21, 22]:
        packet = PacketInfo(
            packet_id=f"p{port}",
            timestamp=1.0 + port,
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            protocol=Protocol.TCP,
        )
        alerts.extend(engine.update_and_detect(packet))
    assert len(alerts) == 0

    # 第3个触发
    packet = PacketInfo(
        packet_id="p23",
        timestamp=4.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=23,
        protocol=Protocol.TCP,
    )
    alerts.extend(engine.update_and_detect(packet))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "BEH-T1"
    assert "distinct destination ports: 3" in alert.evidence


def test_behavior_engine_detects_bruteforce():
    rule = BehaviorRule(
        rule_id="BEH-T2",
        name="test_bruteforce",
        category=AttackCategory.BRUTE_FORCE,
        level=AlertLevel.HIGH,
        event_type="login_attempts",
        window_seconds=60,
        threshold=3,
        group_by=["src_ip", "dst_ip"],
        condition={"http_path_keywords": ["login", "signin"]},
        enabled=True,
        description="Test brute force",
        suggestion="Enable CAPTCHA"
    )
    engine = BehaviorEngine([rule])
    src, dst = "10.0.0.1", "10.0.0.3"

    # 2个登录请求，不触发
    for i in range(2):
        http = HttpInfo(method="POST", path="/login", url="/login?user=test")
        packet = PacketInfo(
            packet_id=f"p{i}",
            timestamp=1.0 + i,
            src_ip=src,
            dst_ip=dst,
            dst_port=80,
            protocol=Protocol.HTTP,
            http=http,
        )
        alerts = engine.update_and_detect(packet)
        assert len(alerts) == 0

    # 第3个触发
    http = HttpInfo(method="POST", path="/login", url="/login?user=admin")
    packet = PacketInfo(
        packet_id="p3",
        timestamp=3.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=80,
        protocol=Protocol.HTTP,
        http=http,
    )
    alerts = engine.update_and_detect(packet)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "BEH-T2"
    assert "login attempts in window: 3" in alert.evidence


def test_behavior_engine_detects_high_frequency():
    rule = BehaviorRule(
        rule_id="BEH-T3",
        name="test_high_freq",
        category=AttackCategory.SUSPICIOUS_TRAFFIC,
        level=AlertLevel.MEDIUM,
        event_type="request_rate",
        window_seconds=10,
        threshold=5,
        group_by=["src_ip", "dst_ip"],
        condition={"protocol": "HTTP"},
        enabled=True,
        description="Test high frequency",
        suggestion="Rate limit"
    )
    engine = BehaviorEngine([rule])
    src, dst = "10.0.0.1", "10.0.0.4"

    for i in range(4):
        http = HttpInfo(method="GET", path="/", url="/")
        packet = PacketInfo(
            packet_id=f"p{i}",
            timestamp=1.0 + i,
            src_ip=src,
            dst_ip=dst,
            dst_port=80,
            protocol=Protocol.HTTP,
            http=http,
        )
        alerts = engine.update_and_detect(packet)
        assert len(alerts) == 0

    # 第5个触发
    http = HttpInfo(method="GET", path="/api", url="/api")
    packet = PacketInfo(
        packet_id="p5",
        timestamp=5.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=80,
        protocol=Protocol.HTTP,
        http=http,
    )
    alerts = engine.update_and_detect(packet)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "BEH-T3"
    assert "requests in window: 5" in alert.evidence


def test_condition_filter():
    rule = BehaviorRule(
        rule_id="BEH-T4",
        name="test_condition",
        category=AttackCategory.PORT_SCAN,
        level=AlertLevel.MEDIUM,
        event_type="distinct_dst_ports",
        window_seconds=60,
        threshold=3,
        group_by=["src_ip", "dst_ip"],
        condition={"protocol": "TCP"},
        enabled=True,
        description="Test condition filter",
        suggestion=""
    )
    engine = BehaviorEngine([rule])
    src, dst = "10.0.0.1", "10.0.0.5"

    # UDP包不计数
    for port in [53, 123, 161]:
        packet = PacketInfo(
            packet_id=f"u{port}",
            timestamp=1.0,
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            protocol=Protocol.UDP,
        )
        alerts = engine.update_and_detect(packet)
        assert len(alerts) == 0

    # 2个TCP包，未达阈值
    for port in [22, 23]:
        packet = PacketInfo(
            packet_id=f"t{port}",
            timestamp=2.0,
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            protocol=Protocol.TCP,
        )
        alerts = engine.update_and_detect(packet)
        assert len(alerts) == 0

    # 第3个TCP包触发
    packet = PacketInfo(
        packet_id="t24",
        timestamp=3.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=24,
        protocol=Protocol.TCP,
    )
    alerts = engine.update_and_detect(packet)
    assert len(alerts) == 1


def test_window_sliding():
    rule = BehaviorRule(
        rule_id="BEH-T5",
        name="test_window",
        category=AttackCategory.PORT_SCAN,
        level=AlertLevel.MEDIUM,
        event_type="distinct_dst_ports",
        window_seconds=2,
        threshold=3,
        group_by=["src_ip", "dst_ip"],
        condition={"protocol": "TCP"},
        enabled=True,
        description="Test window sliding",
        suggestion=""
    )
    engine = BehaviorEngine([rule])
    src, dst = "10.0.0.1", "10.0.0.6"

    # 发送2个端口（时间0,1），未达阈值
    for t, port in enumerate([21, 22]):
        packet = PacketInfo(
            packet_id=f"p{port}",
            timestamp=float(t),
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            protocol=Protocol.TCP,
        )
        alerts = engine.update_and_detect(packet)
        assert len(alerts) == 0

    # 发送第3个端口，时间戳为3（超过窗口2秒），旧状态重置，窗口内只有1个端口
    packet = PacketInfo(
        packet_id="p23",
        timestamp=3.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=23,
        protocol=Protocol.TCP,
    )
    alerts = engine.update_and_detect(packet)
    assert len(alerts) == 0

    # 再发2个端口，时间4,5，窗口内将有3个不同端口（23,24,25）触发
    # 发送24（不触发）
    packet = PacketInfo(
        packet_id="p24",
        timestamp=4.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=24,
        protocol=Protocol.TCP,
    )
    alerts = engine.update_and_detect(packet)
    assert len(alerts) == 0

    # 发送25（触发）
    packet = PacketInfo(
        packet_id="p25",
        timestamp=5.0,
        src_ip=src,
        dst_ip=dst,
        dst_port=25,
        protocol=Protocol.TCP,
    )
    alerts = engine.update_and_detect(packet)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "BEH-T5"
    assert "distinct destination ports: 3" in alert.evidence