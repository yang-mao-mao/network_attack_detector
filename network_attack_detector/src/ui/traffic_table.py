from __future__ import annotations

from src.core.models import PacketInfo


class TrafficTableModel:
    def __init__(self) -> None:
        self.packets: list[PacketInfo] = []

    def add_packet(self, packet: PacketInfo) -> None:
        self.packets.append(packet)

