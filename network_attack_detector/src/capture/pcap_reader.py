from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.exceptions import CaptureError

try:
    from scapy.all import rdpcap
except ImportError:  # pragma: no cover
    rdpcap = None


class PcapReader:
    def read_packets(self, pcap_path: str | Path) -> list[Any]:
        if rdpcap is None:
            raise CaptureError("Scapy is not installed.")
        path = Path(pcap_path)
        if not path.exists():
            raise CaptureError(f"pcap file does not exist: {path}")
        return list(rdpcap(str(path)))

