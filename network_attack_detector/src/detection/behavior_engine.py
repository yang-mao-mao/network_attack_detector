from __future__ import annotations

import time
import uuid

from src.core.models import Alert, BehaviorRule, PacketInfo, Protocol
from src.detection.state_tracker import StateTracker


class BehaviorEngine:
    def __init__(self, rules: list[BehaviorRule]) -> None:
        self.rules = rules
        self.tracker = StateTracker()

    def update_and_detect(self, packet: PacketInfo) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if not rule.enabled or not self._condition_matches(rule, packet):
                continue
            state = self.tracker.get_state(rule, packet)
            state.packet_count += 1
            state.request_count += 1
            if packet.dst_port is not None:
                state.dst_ports.add(packet.dst_port)
            if packet.http and packet.http.path:
                state.urls.add(packet.http.path)

            evidence = self._check_rule(rule, packet, state)
            if evidence:
                alerts.append(self._build_alert(rule, packet, evidence))
        return alerts

    def _check_rule(self, rule: BehaviorRule, packet: PacketInfo, state) -> str | None:
        if rule.event_type == "distinct_dst_ports" and len(state.dst_ports) >= rule.threshold:
            return f"distinct destination ports: {len(state.dst_ports)}"
        if rule.event_type == "login_attempts" and self._is_login_request(rule, packet):
            if state.request_count >= rule.threshold:
                return f"login attempts in window: {state.request_count}"
        if rule.event_type == "request_rate" and state.request_count >= rule.threshold:
            return f"requests in window: {state.request_count}"
        return None

    @staticmethod
    def _condition_matches(rule: BehaviorRule, packet: PacketInfo) -> bool:
        protocol = rule.condition.get("protocol")
        if protocol and packet.protocol.value != protocol:
            return False
        return True

    @staticmethod
    def _is_login_request(rule: BehaviorRule, packet: PacketInfo) -> bool:
        if not packet.http or not packet.http.path:
            return packet.dst_port in {21, 22, 3389}
        keywords = rule.condition.get("http_path_keywords", [])
        path = packet.http.path.lower()
        return any(keyword.lower() in path for keyword in keywords)

    @staticmethod
    def _build_alert(rule: BehaviorRule, packet: PacketInfo, evidence: str) -> Alert:
        return Alert(
            alert_id=f"ALT-{uuid.uuid4().hex[:12]}",
            timestamp=time.time(),
            category=rule.category,
            level=rule.level,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol if packet.protocol else Protocol.UNKNOWN,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            evidence=evidence,
            description=rule.description,
            suggestion=rule.suggestion,
            packet_id=packet.packet_id,
        )

