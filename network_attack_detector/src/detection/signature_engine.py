from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Pattern

from src.core.constants import DEFAULT_PAYLOAD_PREVIEW_LENGTH
from src.core.models import Alert, PacketInfo, Protocol, SignatureRule


logger = logging.getLogger(__name__)


class SignatureEngine:
    """Match packet fields against content and regular-expression rules."""

    # 防止长期运行时已告警数据包集合无限增长。
    MAX_REPORTED_MATCHES = 10_000

    def __init__(self, rules: list[SignatureRule]) -> None:
        self.rules = rules
        self._regex_cache: dict[tuple[str, str, bool], Pattern[str]] = {}
        self._invalid_regex_keys: set[tuple[str, str, bool]] = set()
        self._reported_matches: set[tuple[str, str]] = set()
        self._precompile_regex_rules()

    def detect(self, packet: PacketInfo) -> list[Alert]:
        alerts: list[Alert] = []
        matched_in_call: set[tuple[str, str]] = set()

        for rule in self.rules:
            match_key = (packet.packet_id, rule.rule_id)
            # 同一规则和数据包即使重复配置或重复送检也只告警一次。
            if match_key in matched_in_call or match_key in self._reported_matches:
                continue

            try:
                if not rule.enabled:
                    continue
                if rule.protocol not in {Protocol.UNKNOWN, packet.protocol}:
                    continue

                match = self._match_rule(rule, packet)
                if match is None:
                    continue

                matched_field, evidence = match
                alerts.append(self._build_alert(rule, packet, matched_field, evidence))
                matched_in_call.add(match_key)
                self._remember_reported_match(match_key)
            except Exception as exc:  # 单条错误规则不应中断其他规则检测。
                logger.warning(
                    "Skipping invalid signature rule %s for packet %s: %s",
                    getattr(rule, "rule_id", "<unknown>"),
                    getattr(packet, "packet_id", "<unknown>"),
                    exc,
                )

        return alerts

    def _match_rule(
        self,
        rule: SignatureRule,
        packet: PacketInfo,
    ) -> tuple[str, str] | None:
        # target_fields 为空时明确回退到 payload_text。
        target_fields = rule.target_fields or ["payload_text"]

        # 依次检查所有目标字段，但一条规则对一个数据包只返回首次命中。
        for field_name in target_fields:
            value = self._get_field(packet, field_name)
            if value is None:
                continue
            text = str(value)

            if rule.match_type == "content":
                if not isinstance(rule.pattern, str) or not rule.pattern:
                    raise ValueError("content pattern must not be empty")
                source = text.lower() if rule.nocase else text
                target = rule.pattern.lower() if rule.nocase else rule.pattern
                start = source.find(target)
                if start >= 0:
                    # 返回实际命中文本，而不是规则中可能大小写不同的 pattern。
                    evidence = text[start : start + len(rule.pattern)]
                    return field_name, self._truncate_evidence(evidence)

            elif rule.match_type == "regex":
                compiled = self._get_compiled_regex(rule)
                if compiled is None:
                    return None
                found = compiled.search(text)
                if found:
                    return field_name, self._truncate_evidence(found.group(0))
            else:
                raise ValueError(f"unsupported match_type: {rule.match_type!r}")

        return None

    def _precompile_regex_rules(self) -> None:
        """启动时预编译正则；无效规则仅被标记和跳过。"""
        for rule in self.rules:
            if rule.match_type == "regex":
                self._get_compiled_regex(rule)

    def _get_compiled_regex(self, rule: SignatureRule) -> Pattern[str] | None:
        key = (rule.rule_id, rule.pattern, bool(rule.nocase))
        if key in self._regex_cache:
            return self._regex_cache[key]
        if key in self._invalid_regex_keys:
            return None

        try:
            flags = re.IGNORECASE if rule.nocase else 0
            compiled = re.compile(rule.pattern, flags)
        except (TypeError, re.error) as exc:
            self._invalid_regex_keys.add(key)
            logger.warning("Ignoring invalid regex rule %s: %s", rule.rule_id, exc)
            return None

        self._regex_cache[key] = compiled
        return compiled

    @staticmethod
    def _get_field(packet: PacketInfo, field_name: str) -> object | None:
        if field_name == "payload_text":
            return packet.payload_text
        if field_name.startswith("http.") and packet.http:
            return getattr(packet.http, field_name.split(".", 1)[1], None)
        return getattr(packet, field_name, None)

    @staticmethod
    def _truncate_evidence(evidence: str) -> str:
        if len(evidence) <= DEFAULT_PAYLOAD_PREVIEW_LENGTH:
            return evidence
        return evidence[:DEFAULT_PAYLOAD_PREVIEW_LENGTH] + "..."

    def _remember_reported_match(self, match_key: tuple[str, str]) -> None:
        if len(self._reported_matches) >= self.MAX_REPORTED_MATCHES:
            self._reported_matches.clear()
        self._reported_matches.add(match_key)

    @staticmethod
    def _build_alert(
        rule: SignatureRule,
        packet: PacketInfo,
        matched_field: str,
        evidence: str,
    ) -> Alert:
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
            extra={
                "matched_field": matched_field,
                "match_type": rule.match_type,
            },
        )
