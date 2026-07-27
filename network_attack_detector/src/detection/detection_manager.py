from __future__ import annotations

import time

from ..core.models import DetectionResult, PacketInfo
from ..detection.behavior_engine import BehaviorEngine
from ..detection.signature_engine import SignatureEngine


class DetectionManager:
    def __init__(self,
                 signature_engine:SignatureEngine,
                 behavior_engine:BehaviorEngine):
        self.signature_engine=signature_engine
        self.behavior_engine=behavior_engine
        
    def detect(self,packet:PacketInfo):
        start_time=time.time()
        matched=False
        signature_result=self.signature_engine.detect(packet) 
        behavior_result=self.behavior_engine.update_and_detect(packet)
        alerts = [*signature_result,*behavior_result]
        if len(alerts)>0:
            matched=True
        end_time=time.time()
        cost_ms=(end_time-start_time)*1000
        return DetectionResult(packet.packet_id,matched,alerts,"DetectionManager",cost_ms)
    
            
            
        
    

