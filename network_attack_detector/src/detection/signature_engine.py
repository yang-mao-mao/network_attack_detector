from __future__ import annotations

import re
import time
import uuid

from src.core.models import Alert, PacketInfo, Protocol, SignatureRule


class SignatureEngine:
    def __init__(self, rules: list[SignatureRule]) -> None:
        self.rules = rules

    def detect(self, packet: PacketInfo) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.protocol not in {Protocol.UNKNOWN, packet.protocol}:
                continue
            match = self._match_rule(rule, packet)
            if match:
                alerts.append(self._build_alert(rule, packet, match))
        return alerts

    def _match_rule(self, rule: SignatureRule, packet: PacketInfo) -> str | None:
        values = [self._get_field(packet, field) for field in rule.target_fields]
        if not values:
            values = [packet.payload_text]

        for value in values:
            if value is None:
                continue
            text = str(value)
            if rule.match_type == "content":
                source = text.lower() if rule.nocase else text
                target = rule.pattern.lower() if rule.nocase else rule.pattern
                if target in source:
                    return rule.pattern
            elif rule.match_type == "regex":
                flags = re.IGNORECASE if rule.nocase else 0
                found = re.search(rule.pattern, text, flags)
                if found:
                    return found.group(0)
        return None

    @staticmethod
    def _get_field(packet: PacketInfo, field_name: str) -> str | None:
        if field_name == "payload_text":
            return packet.payload_text
        if field_name.startswith("http.") and packet.http:
            return getattr(packet.http, field_name.split(".", 1)[1], None)
        return getattr(packet, field_name, None)

    @staticmethod
    def _build_alert(rule: SignatureRule, packet: PacketInfo, evidence: str) -> Alert:
        return Alert(
            alert_id=f"ALT-{uuid.uuid4().hex[:12]}",
            timestamp=time.time(),
            category=rule.category,
            level=rule.level,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            evidence=evidence,
            description=rule.description,
            suggestion=rule.suggestion,
            packet_id=packet.packet_id,
        )

