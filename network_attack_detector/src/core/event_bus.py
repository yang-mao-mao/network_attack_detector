from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[Any], None]]] = defaultdict(list)

    def subscribe(self, event_name: str, handler: Callable[[Any], None]) -> None:
        if handler in self._handlers[event_name]:
            return
        self._handlers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: Callable[[Any], None]) -> None:
        handlers = self._handlers.get(event_name)
        if not handlers:
            return

        if handler in handlers:
            handlers.remove(handler)

        if not handlers:
            self._handlers.pop(event_name, None)

    def publish(self, event_name: str, payload: Any = None) -> None:
        for handler in list(self._handlers.get(event_name, [])):
            handler(payload)

    def clear(self) -> None:
        self._handlers.clear()
