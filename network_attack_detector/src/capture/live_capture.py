from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from src.capture.interface import CaptureInterface
from src.core.exceptions import CaptureError

try:
    from scapy.all import get_if_list, sniff
except ImportError:  # pragma: no cover
    get_if_list = None
    sniff = None


class LiveCapture(CaptureInterface):
    def __init__(self, bpf_filter: str = "ip and tcp") -> None:
        self.bpf_filter = bpf_filter
        self._running = False
        self._thread: threading.Thread | None = None

    def list_interfaces(self) -> list[str]:
        if get_if_list is None:
            raise CaptureError("Scapy is not installed.")
        return list(get_if_list())

    def start_capture(self, interface: str, packet_callback: Callable[[Any], None]) -> None:
        if sniff is None:
            raise CaptureError("Scapy is not installed.")
        if self._running:
            return

        self._running = True

        def _run() -> None:
            sniff(
                iface=interface,
                filter=self.bpf_filter,
                prn=packet_callback,
                store=False,
                stop_filter=lambda _: not self._running,
            )

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop_capture(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

