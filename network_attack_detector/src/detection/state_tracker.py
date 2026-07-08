from __future__ import annotations

from src.core.models import BehaviorRule, FlowState, PacketInfo


class StateTracker:
    def __init__(self) -> None:
        self.states: dict[str, FlowState] = {}

    def get_state(self, rule: BehaviorRule, packet: PacketInfo) -> FlowState:
        key = self._make_key(rule, packet)
        state = self.states.get(key)
        if state is None or packet.timestamp - state.first_seen > rule.window_seconds:
            state = FlowState(key=key, first_seen=packet.timestamp, last_seen=packet.timestamp)
            self.states[key] = state
        state.last_seen = packet.timestamp
        return state

    @staticmethod
    def _make_key(rule: BehaviorRule, packet: PacketInfo) -> str:
        values = [str(getattr(packet, field, "")) for field in rule.group_by]
        return f"{rule.rule_id}:" + "|".join(values)

