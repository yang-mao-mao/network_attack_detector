from __future__ import annotations

import time
from typing import Optional

from src.core.models import BehaviorRule, FlowState, PacketInfo, Protocol


class StateTracker:
    """
    行为检测状态跟踪器

    维护每个分组键（rule_id + group_by 字段组合）的 FlowState，
    支持滑动窗口过期重置，并提供状态重置和清理功能。
    """

    def __init__(self) -> None:
        self.states: dict[str, FlowState] = {}

    def get_state(self, rule: BehaviorRule, packet: PacketInfo) -> FlowState:
        """
        获取或创建状态对象，自动处理窗口过期重置。

        若状态不存在或距离 first_seen 超过 window_seconds，则创建新状态。
        """
        key = self._make_key(rule, packet)
        state = self.states.get(key)
        if state is None or packet.timestamp - state.first_seen > rule.window_seconds:
            state = FlowState(key=key, first_seen=packet.timestamp, last_seen=packet.timestamp)
            self.states[key] = state
        state.last_seen = packet.timestamp
        return state

    @staticmethod
    def _make_key(rule: BehaviorRule, packet: PacketInfo) -> str:
        """根据规则的 group_by 字段和 rule_id 生成唯一状态键。格式: rule_id:field1|field2|..."""
        values = [str(getattr(packet, field, "")) for field in rule.group_by]
        return f"{rule.rule_id}:" + "|".join(values)

    def reset_state(self, rule: BehaviorRule, packet: PacketInfo) -> None:
        """
        重置指定规则对应的状态（通常在告警触发后调用）。
        使用当前包时间戳重置 first_seen 和 last_seen，并清空所有统计。
        """
        key = self._make_key(rule, packet)
        if key in self.states:
            self.states[key] = FlowState(
                key=key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp
            )

    def cleanup_expired(self, max_age: float = 3600.0) -> None:
        """清理超过最大空闲时间（默认 3600 秒）的陈旧状态，基于 last_seen 判断。"""
        now = time.time()
        expired = [k for k, st in self.states.items() if now - st.last_seen > max_age]
        for k in expired:
            del self.states[k]

    # ---------- 以下为可选辅助方法（不强制 behavior_engine 使用） ----------
    def _match_condition(self, packet: PacketInfo, condition: dict) -> bool:
        """检查数据包是否满足规则的 condition（供其他模块使用）。"""
        if not condition:
            return True
        if "protocol" in condition:
            proto_str = condition["protocol"].upper()
            try:
                proto_enum = Protocol[proto_str]
            except KeyError:
                return False
            if packet.protocol != proto_enum:
                return False
        if "http_path_keywords" in condition:
            keywords = condition["http_path_keywords"]
            if not packet.http or not packet.http.path:
                return False
            if not any(kw in packet.http.path for kw in keywords):
                return False
        return True

    def update_state(self, rule: BehaviorRule, packet: PacketInfo) -> Optional[str]:
        """
        根据规则更新状态，返回状态键；若条件不匹配则返回 None。
        该方法与 behavior_engine 当前逻辑不冲突，可作为替代方案。
        """
        if not self._match_condition(packet, rule.condition):
            return None
        state = self.get_state(rule, packet)
        event_type = rule.event_type
        if event_type == "distinct_dst_ports":
            if packet.dst_port is not None:
                state.dst_ports.add(packet.dst_port)
        elif event_type == "login_attempts":
            state.failed_login_count += 1
            if packet.http and packet.http.url:
                state.urls.add(packet.http.url)
        elif event_type == "request_rate":
            state.request_count += 1
            if packet.http and packet.http.url:
                state.urls.add(packet.http.url)
        else:
            return None
        return state.key