from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.models import Alert, DetectionResult, PacketInfo, Protocol
from src.detection.behavior_engine import BehaviorEngine
from src.detection.detection_manager import DetectionManager
from src.detection.signature_engine import SignatureEngine
from src.parser.packet_parser import PacketParser
from src.rules.rule_loader import RuleLoader
from src.storage.rule_repository import RuleRepository


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class DemoDetectionItem:
    name: str
    packet: PacketInfo
    result: DetectionResult


@dataclass(frozen=True)
class DemoDataset:
    items: list[DemoDetectionItem]

    @property
    def packets(self) -> list[PacketInfo]:
        return [item.packet for item in self.items]

    @property
    def results(self) -> list[DetectionResult]:
        return [item.result for item in self.items]

    @property
    def alerts(self) -> list[Alert]:
        return [alert for item in self.items for alert in item.result.alerts]


def build_demo_dataset(project_root: Path | None = None) -> DemoDataset:
    """Build reproducible traffic and run it through the real detector."""
    root = project_root or PROJECT_ROOT
    rules_dir = root / "data" / "rules"

    loader = RuleLoader()
    signature_rules = loader.load_signature_rules(rules_dir / "signature_rules.csv")
    behavior_rules = loader.load_behavior_rules(rules_dir / "behavior_rules.json")
    repository = RuleRepository(signature_rules, behavior_rules)

    manager = DetectionManager(
        signature_engine=SignatureEngine(
            repository.list_signature_rules(enabled_only=True)
        ),
        behavior_engine=BehaviorEngine(
            repository.list_behavior_rules(enabled_only=True)
        ),
    )

    parser = PacketParser()
    packets = _build_packets(parser)
    items: list[DemoDetectionItem] = []
    for name, packet in packets:
        result = manager.detect(packet)
        items.append(DemoDetectionItem(name=name, packet=packet, result=result))
    return DemoDataset(items=items)


def write_demo_files(output_dir: Path | None = None) -> dict[str, Any]:
    """Write demo traffic and a detection summary into data/samples."""
    dataset = build_demo_dataset()
    target_dir = output_dir or PROJECT_ROOT / "data" / "samples"
    target_dir.mkdir(parents=True, exist_ok=True)

    traffic_path = target_dir / "demo_traffic.json"
    summary_path = target_dir / "demo_summary.json"

    traffic_records = [
        {
            "name": item.name,
            "packet": _packet_to_record(item.packet),
            "matched": item.result.matched,
            "alerts": [_alert_to_record(alert) for alert in item.result.alerts],
        }
        for item in dataset.items
    ]

    category_counts = Counter(alert.category.value for alert in dataset.alerts)
    rule_counts = Counter(alert.rule_id for alert in dataset.alerts)
    summary = {
        "packet_count": len(dataset.packets),
        "matched_packet_count": sum(1 for item in dataset.items if item.result.matched),
        "alert_count": len(dataset.alerts),
        "alerts_by_category": dict(sorted(category_counts.items())),
        "alerts_by_rule": dict(sorted(rule_counts.items())),
    }

    traffic_path.write_text(
        json.dumps(traffic_records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return {
        "traffic_path": traffic_path,
        "summary_path": summary_path,
        **summary,
    }


def filter_result_by_rule_prefix(
    result: DetectionResult,
    rule_prefix: str,
    engine_name: str,
) -> DetectionResult | None:
    alerts = [
        alert for alert in result.alerts
        if alert.rule_id.startswith(rule_prefix)
    ]
    if not alerts:
        return None
    return DetectionResult(
        packet_id=result.packet_id,
        matched=True,
        alerts=alerts,
        engine_name=engine_name,
        cost_ms=result.cost_ms,
    )


def _build_packets(parser: PacketParser) -> list[tuple[str, PacketInfo]]:
    base_time = time.time()
    packets: list[tuple[str, PacketInfo]] = []

    script_payload = "%3C" + "script%3Ealert(1)%3C/" + "script%3E"
    cmd_marker = "cmd" + ".exe%20/" + "c%20whoami"
    http_cases = [
        (
            "normal-home-page",
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: demo.local\r\n"
            b"User-Agent: securelog-demo\r\n"
            b"\r\n",
            "192.168.10.5",
            51000,
        ),
        (
            "sql-injection-union-select",
            b"GET /search?q=1%20union%20select%20password%20from%20users HTTP/1.1\r\n"
            b"Host: demo.local\r\n"
            b"User-Agent: securelog-demo\r\n"
            b"\r\n",
            "192.168.10.10",
            51001,
        ),
        (
            "xss-script-tag",
            f"GET /comment?text={script_payload} HTTP/1.1\r\n"
            f"Host: demo.local\r\n"
            f"User-Agent: securelog-demo\r\n"
            f"\r\n",
            "192.168.10.11",
            51002,
        ),
        (
            "command-injection-windows-cmd",
            f"GET /run?cmd={cmd_marker} HTTP/1.1\r\n"
            f"Host: demo.local\r\n"
            f"User-Agent: securelog-demo\r\n"
            f"\r\n",
            "192.168.10.12",
            51003,
        ),
    ]

    for index, (name, payload, src_ip, src_port) in enumerate(http_cases, start=1):
        raw_payload = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        packet = parser.parse_http_bytes(
            raw_payload,
            src_ip=src_ip,
            dst_ip="10.0.0.10",
            src_port=src_port,
            dst_port=80,
        )
        _stamp_packet(packet, f"DEMO-HTTP-{index:02d}", base_time + index, name)
        packets.append((name, packet))

    port_scan_ports = [
        20, 21, 22, 23, 25, 53, 80, 110, 135, 139,
        143, 443, 445, 993, 995, 1433, 1521, 3306, 5432, 8080,
    ]
    for offset, port in enumerate(port_scan_ports, start=len(packets) + 1):
        packet = PacketInfo(
            packet_id=f"DEMO-PORTSCAN-{offset:02d}",
            timestamp=base_time + offset,
            src_ip="192.168.20.50",
            dst_ip="10.0.0.20",
            src_port=40000 + offset,
            dst_port=port,
            protocol=Protocol.TCP,
            length=60,
            raw_summary=f"demo TCP SYN scan to port {port}",
            metadata={"demo_name": "port-scan"},
        )
        packets.append((f"port-scan-{port}", packet))

    login_start = len(packets) + 1
    for attempt in range(1, 11):
        payload = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: demo.local\r\n"
            f"User-Agent: securelog-demo\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"\r\n"
            f"username=admin&password=bad{attempt}"
        ).encode("utf-8")
        packet = parser.parse_http_bytes(
            payload,
            src_ip="192.168.30.77",
            dst_ip="10.0.0.30",
            src_port=52000 + attempt,
            dst_port=80,
        )
        index = login_start + attempt - 1
        _stamp_packet(packet, f"DEMO-BRUTE-{attempt:02d}", base_time + index, "brute-force-login")
        packets.append((f"brute-force-login-{attempt:02d}", packet))

    return packets


def _stamp_packet(packet: PacketInfo, packet_id: str, timestamp: float, name: str) -> None:
    packet.packet_id = packet_id
    packet.timestamp = timestamp
    packet.raw_summary = name
    packet.metadata["demo_name"] = name


def _packet_to_record(packet: PacketInfo) -> dict[str, Any]:
    http = packet.http
    return {
        "packet_id": packet.packet_id,
        "timestamp": packet.timestamp,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "protocol": packet.protocol.value,
        "length": packet.length,
        "payload_text": packet.payload_text,
        "raw_summary": packet.raw_summary,
        "http": None if http is None else {
            "method": http.method,
            "host": http.host,
            "url": http.url,
            "path": http.path,
            "query": http.query,
            "user_agent": http.user_agent,
            "body": http.body,
        },
    }


def _alert_to_record(alert: Alert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "category": alert.category.value,
        "level": alert.level.value,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "evidence": alert.evidence,
        "description": alert.description,
        "suggestion": alert.suggestion,
        "packet_id": alert.packet_id,
    }
