from __future__ import annotations

import time

from src.core.models import DetectionResult, PacketInfo
from src.detection.behavior_engine import BehaviorEngine
from src.detection.signature_engine import SignatureEngine


class DetectionManager:
    def __init__(self, signature_engine: SignatureEngine, behavior_engine: BehaviorEngine) -> None:
        self.signature_engine = signature_engine
        self.behavior_engine = behavior_engine

    def detect(self, packet: PacketInfo) -> DetectionResult:
        started = time.perf_counter()
        alerts = []
        alerts.extend(self.signature_engine.detect(packet))
        alerts.extend(self.behavior_engine.update_and_detect(packet))
        return DetectionResult(
            packet_id=packet.packet_id,
            matched=bool(alerts),
            alerts=alerts,
            engine_name="DetectionManager",
            cost_ms=(time.perf_counter() - started) * 1000,
        )

