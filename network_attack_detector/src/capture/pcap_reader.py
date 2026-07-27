from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from src.core.exceptions import CaptureError
from src.core.models import PcapPacket

try:
    from scapy.all import PcapReader as ScapyPcapReader
    from scapy.all import rdpcap
except ImportError:  # pragma: no cover
    ScapyPcapReader = None
    rdpcap = None


class PcapReader:
    """Read pcap files with both batch and streaming APIs."""

    def __init__(self, pcap_path: str | Path | None = None) -> None:
        self.path = Path(pcap_path) if pcap_path is not None else None
        self._packets: list[Any] | None = None

    def read_packets(self, pcap_path: str | Path | None = None) -> list[Any]:
        path = self._resolve_path(pcap_path)
        if rdpcap is None:
            raise CaptureError("Scapy is not installed.")
        return list(rdpcap(str(path)))

    def read_all(self) -> list[Any]:
        if self._packets is None:
            self._packets = self.read_packets()
        return list(self._packets)

    def stream(self, pcap_path: str | Path | None = None) -> Iterator[PcapPacket]:
        path = self._resolve_path(pcap_path)
        if ScapyPcapReader is None:
            raise CaptureError("Scapy is not installed.")

        reader = ScapyPcapReader(str(path))
        try:
            for index, packet in enumerate(reader, start=1):
                yield PcapPacket(
                    index=index,
                    timestamp=float(getattr(packet, "time", 0.0)),
                    raw_packet=packet,
                )
        finally:
            reader.close()

    def filter(
        self,
        predicate: Callable[[PcapPacket], bool],
    ) -> Iterator[PcapPacket]:
        for packet in self.stream():
            if predicate(packet):
                yield packet

    def find_first(
        self,
        predicate: Callable[[PcapPacket], bool],
    ) -> PcapPacket | None:
        for packet in self.stream():
            if predicate(packet):
                return packet
        return None

    def slice(
        self,
        start: int = 0,
        end: int | None = None,
        step: int = 1,
    ) -> Iterator[PcapPacket]:
        for index, packet in enumerate(self.stream()):
            if index < start:
                continue
            if end is not None and index >= end:
                break
            if (index - start) % step == 0:
                yield packet

    def stats(self) -> dict[str, Any]:
        protocol_counts: dict[str, int] = {}
        total = 0

        for packet in self.stream():
            total += 1
            try:
                protocol = packet.raw_packet.lastlayer().name
            except Exception:
                protocol = "UNKNOWN"
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        return {
            "file": str(self._resolve_path()),
            "total_packets": total,
            "protocols": protocol_counts,
        }

    def time_range(self) -> tuple[float, float] | None:
        first: float | None = None
        last: float | None = None
        for packet in self.stream():
            if first is None:
                first = packet.timestamp
            last = packet.timestamp
        if first is None or last is None:
            return None
        return first, last

    def tcp_stream(self) -> Iterator[PcapPacket]:
        return self.filter(lambda packet: packet.raw_packet.haslayer("TCP"))

    def udp_stream(self) -> Iterator[PcapPacket]:
        return self.filter(lambda packet: packet.raw_packet.haslayer("UDP"))

    def http_packets(self) -> Iterator[PcapPacket]:
        def is_http(packet: PcapPacket) -> bool:
            if not packet.raw_packet.haslayer("TCP"):
                return False
            tcp_layer = packet.raw_packet["TCP"]
            return tcp_layer.dport in {80, 8080} or tcp_layer.sport in {80, 8080}

        return self.filter(is_http)

    def ip_between(self, first_ip: str, second_ip: str) -> Iterator[PcapPacket]:
        ip_pair = {first_ip, second_ip}

        def matches(packet: PcapPacket) -> bool:
            return packet.raw_packet.haslayer("IP") and {
                packet.raw_packet["IP"].src,
                packet.raw_packet["IP"].dst,
            } == ip_pair

        return self.filter(matches)

    def __iter__(self) -> Iterator[PcapPacket]:
        return self.stream()

    def __len__(self) -> int:
        return sum(1 for _ in self.stream())

    def _resolve_path(self, pcap_path: str | Path | None = None) -> Path:
        path = Path(pcap_path) if pcap_path is not None else self.path
        if path is None:
            raise CaptureError("pcap path is required.")
        if not path.exists():
            raise CaptureError(f"pcap file does not exist: {path}")
        if not path.is_file():
            raise CaptureError(f"pcap path is not a file: {path}")
        return path
