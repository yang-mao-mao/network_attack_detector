from __future__ import annotations
from typing import Callable
from typing import Any
from collections import defaultdict
class EventBus:
    #初始化函数声明了一个字典,键是事件,值是一个列表。并且使用defaultdict对其进行赋值
    #当键第一次被访问的时候，值默认为空列表
    def __init__(self)->None:
        self._handlers :dict[str,list[Callable[[Any],None]]]=defaultdict(list)
    
    #订阅函数
    def subscribe(self,event_name:str,handler:Callable[[Any],None])->None:
        if handler in self._handlers[event_name]:
            return

        self._handlers[event_name].append(handler)
    #退订函数
    def unsubscribe(self,event_name:str,handler:Callable[[Any],None])->None:
        if event_name not in self._handlers:
            return 
        if handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)
        if not self._handlers[event_name]:
            self._handlers.pop(event_name)
    

    #激活函数
    def publish(self,event_name:str,payload:Any=None)->None:
        if event_name not in self._handlers:
            return 
        else:
            for handler in list(self._handlers.get(event_name,[])):
                handler(payload)

    def clear(self)->None:
        self._handlers.clear()
