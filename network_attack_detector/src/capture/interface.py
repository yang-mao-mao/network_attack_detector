from __future__ import annotations

from collections.abc import Callable
from typing import Any


class CaptureInterface:
    def list_interfaces(self) -> list[str]:
        raise NotImplementedError

    def start_capture(self, interface: str, packet_callback: Callable[[Any], None]) -> None:
        raise NotImplementedError

    def stop_capture(self) -> None:
        raise NotImplementedError

