from __future__ import annotations

import time
import uuid
from typing import Any

from src.core.models import PacketInfo, Protocol
from src.parser.http_parser import HttpParser
from src.parser.payload_decoder import decode_payload

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Raw
except ImportError:  # pragma: no cover
    ICMP = IP = TCP = UDP = Raw = None


class PacketParser:
    def __init__(self) -> None:
        self.http_parser = HttpParser()

    def parse(self, raw_packet: Any, interface: str | None = None) -> PacketInfo:
        if IP is None:
            raise RuntimeError("Scapy is required to parse live packets.")

        payload = bytes(raw_packet[Raw].load) if Raw is not None and raw_packet.haslayer(Raw) else b""
        payload_text = decode_payload(payload)

        packet = PacketInfo(
            packet_id=self._new_packet_id(),
            timestamp=float(getattr(raw_packet, "time", time.time())),
            length=len(raw_packet),
            payload=payload,
            payload_text=payload_text,
            raw_summary=raw_packet.summary(),
            interface=interface,
        )

        if raw_packet.haslayer(IP):
            packet.src_ip = raw_packet[IP].src
            packet.dst_ip = raw_packet[IP].dst

        if raw_packet.haslayer(TCP):
            packet.protocol = Protocol.TCP
            packet.src_port = int(raw_packet[TCP].sport)
            packet.dst_port = int(raw_packet[TCP].dport)
            packet.metadata["tcp_flags"] = str(raw_packet[TCP].flags)
        elif raw_packet.haslayer(UDP):
            packet.protocol = Protocol.UDP
            packet.src_port = int(raw_packet[UDP].sport)
            packet.dst_port = int(raw_packet[UDP].dport)
        elif raw_packet.haslayer(ICMP):
            packet.protocol = Protocol.ICMP

        http = self.http_parser.parse(payload_text)
        if http:
            packet.protocol = Protocol.HTTP
            packet.http = http

        return packet

    def parse_http_bytes(
        self,
        payload: bytes,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 50000,
        dst_port: int = 80,
    ) -> PacketInfo:
        payload_text = decode_payload(payload)
        return PacketInfo(
            packet_id=self._new_packet_id(),
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=Protocol.HTTP,
            length=len(payload),
            payload=payload,
            payload_text=payload_text,
            http=self.http_parser.parse(payload_text),
            raw_summary="synthetic HTTP request",
        )

    @staticmethod
    def _new_packet_id() -> str:
        return f"PKT-{uuid.uuid4().hex[:12]}"

