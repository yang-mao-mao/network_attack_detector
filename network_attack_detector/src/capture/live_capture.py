from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.capture.interface import CaptureInterface
from src.core.exceptions import CaptureError
from src.core.models import CaptureState

try:
    from scapy.all import AsyncSniffer, get_if_list
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether
except ImportError:  # pragma: no cover
    AsyncSniffer = get_if_list = Ether = IP = TCP = UDP = ICMP = None


@dataclass
class CapturedPacketInfo:
    timestamp: float
    interface: str
    src_mac: str | None
    dst_mac: str | None
    eth_type: str | None
    src_ip: str | None
    dst_ip: str | None
    protocol: str | None
    src_port: int | None
    dst_port: int | None
    length: int
    raw_packet: Any

    def summary(self) -> str:
        return (
            f"[{self.interface}] {self.protocol or 'UNKNOWN'} "
            f"{self.src_ip or self.src_mac}:{self.src_port or '-'} -> "
            f"{self.dst_ip or self.dst_mac}:{self.dst_port or '-'} "
            f"({self.length} bytes)"
        )


class LiveCapture(CaptureInterface):
    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str = "",
        packet_count: int = 0,
        promiscuous: bool = True,
        buffer_size: int = 65536,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size

        self._state = CaptureState.IDLE
        self._sniffer: Any | None = None
        self._handlers: list[Callable[[CapturedPacketInfo], None]] = []
        self._lock = threading.Lock()
        self._stats: dict[str, int] = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "dropped": 0,
        }

    def list_interfaces(self) -> list[str]:
        if get_if_list is not None:
            return list(get_if_list())
        return [item.name for item in CaptureInterface.get_interfaces()]

    @staticmethod
    def validate_filter(bpf_filter: str) -> bool:
        invalid_chars = set(";|&$`")
        return not any(char in bpf_filter for char in invalid_chars)

    def start_capture(
        self,
        interface: str,
        packet_callback: Callable[[Any], None],
    ) -> None:
        self.interface = interface
        self.add_handler(packet_callback)
        self.start()

    def stop_capture(self) -> None:
        self.stop()

    def start(self) -> bool:
        if AsyncSniffer is None:
            raise CaptureError("Scapy is not installed.")
        if not self.validate_filter(self.bpf_filter):
            raise CaptureError(f"Invalid BPF filter: {self.bpf_filter}")

        with self._lock:
            if self._state == CaptureState.RUNNING:
                return False
            self._state = CaptureState.RUNNING

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=self._on_packet_raw,
            count=self.packet_count,
            promisc=self.promiscuous,
            store=False,
        )
        self._sniffer.start()
        return True

    def stop(self) -> None:
        with self._lock:
            if self._state not in {CaptureState.RUNNING, CaptureState.PAUSED}:
                return
            self._state = CaptureState.STOPPED

        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            finally:
                self._sniffer = None

    def pause(self) -> bool:
        with self._lock:
            if self._state != CaptureState.RUNNING:
                return False
            self._state = CaptureState.PAUSED
        return True

    def resume(self) -> bool:
        with self._lock:
            if self._state != CaptureState.PAUSED:
                return False
            self._state = CaptureState.RUNNING
        return True

    def add_handler(self, handler: Callable[[CapturedPacketInfo], None]) -> None:
        self._handlers.append(handler)

    def remove_handler(self, handler: Callable[[CapturedPacketInfo], None]) -> None:
        if handler in self._handlers:
            self._handlers.remove(handler)

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    @property
    def state(self) -> CaptureState:
        return self._state

    def _on_packet_raw(self, packet: Any) -> None:
        with self._lock:
            if self._state != CaptureState.RUNNING:
                return

        try:
            packet_info = self._parse_packet(packet)
        except Exception:
            with self._lock:
                self._stats["dropped"] += 1
            return

        self._update_stats(packet_info)
        for handler in list(self._handlers):
            try:
                handler(packet_info)
            except Exception:
                with self._lock:
                    self._stats["dropped"] += 1

    def _parse_packet(self, packet: Any) -> CapturedPacketInfo:
        timestamp = float(getattr(packet, "time", time.time()))
        interface = self.interface or "unknown"
        length = len(packet)

        src_mac = dst_mac = eth_type = None
        if Ether is not None and packet.haslayer(Ether):
            ether = packet[Ether]
            src_mac = ether.src
            dst_mac = ether.dst
            eth_type = hex(ether.type) if ether.type else None

        src_ip = dst_ip = protocol = None
        src_port = dst_port = None

        if IP is not None and packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if TCP is not None and packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocol = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
            elif UDP is not None and packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocol = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif ICMP is not None and packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = f"IP-{ip_layer.proto}"
        else:
            protocol = "NON-IP"

        return CapturedPacketInfo(
            timestamp=timestamp,
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_type=eth_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            raw_packet=packet,
        )

    def _update_stats(self, packet_info: CapturedPacketInfo) -> None:
        with self._lock:
            self._stats["total"] += 1
            if packet_info.protocol == "TCP":
                self._stats["tcp"] += 1
            elif packet_info.protocol == "UDP":
                self._stats["udp"] += 1
            elif packet_info.protocol == "ICMP":
                self._stats["icmp"] += 1
            else:
                self._stats["other"] += 1
