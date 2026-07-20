from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any,Optional,List,Dict
import urllib.parse

#预定义数据结构，我们的工作流程如下
#获取数据包信息，数据包信息以原始报文的形式给出
#首先，根据数据包的类型对其分类
#接着，针对不同类型的数据包，提取其特征信息
#



class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    ARP = "ARP"
    UNKNOWN = "UNKNOWN"


class AlertLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AttackCategory(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    COMMAND_INJECTION = "Command Injection"
    WEBSHELL = "WebShell"
    BRUTE_FORCE = "Brute Force"
    PORT_SCAN = "Port Scan"
    MALWARE = "Malware"
    SUSPICIOUS_TRAFFIC = "Suspicious Traffic"
    UNKNOWN = "Unknown"

class CaptureState(Enum):
    """抓包状态的枚举类"""
    IDLE = auto()       # 空闲
    RUNNING = auto()    # 运行中
    PAUSED = auto()     # 已暂停
    STOPPED = auto()    # 已停止
    ERROR = auto()      # 出错
@dataclass
class HttpInfo:
    method: str | None = None
    host: str | None = None
    url: str | None = None
    path: str | None = None
    query: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

@dataclass
class PacketInfo:
    packet_id: str
    timestamp: float
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: Protocol = Protocol.UNKNOWN
    length: int = 0
    payload: bytes = b""
    payload_text: str = ""
    http: HttpInfo | None = None
    raw_summary: str = ""
    interface: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    
@dataclass
class SignatureRule:
    rule_id: str
    name: str
    category: AttackCategory
    level: AlertLevel
    protocol: Protocol
    match_type: str
    pattern: str
    target_fields: list[str] = field(default_factory=list)
    nocase: bool = True        #是否区分大小写
    enabled: bool = True       #是否启用
    description: str = ""
    suggestion: str = ""


@dataclass
class BehaviorRule:
    rule_id: str
    name: str
    category: AttackCategory
    level: AlertLevel
    event_type: str
    window_seconds: int      #时间窗口，看多久之前的数据
    threshold: int           #触发阈值
    group_by: list[str] = field(default_factory=list)             #分组字段
    condition: dict[str, Any] = field(default_factory=dict)       #过滤条件
    enabled: bool = True
    description: str = ""
    suggestion: str = ""


@dataclass
class Alert:
    alert_id: str
    timestamp: float
    category: AttackCategory
    level: AlertLevel
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: Protocol
    rule_id: str
    rule_name: str
    evidence: str
    description: str
    suggestion: str = ""
    packet_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowState:
    key: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    request_count: int = 0
    dst_ports: set[int] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    failed_login_count: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    packet_id: str
    matched: bool
    alerts: list[Alert] = field(default_factory=list)
    engine_name: str = ""
    cost_ms: float = 0.0

@dataclass
class PcapPacket:
    """解析后的 pcap 数据包信息"""
    index: int              # 在文件中的序号
    timestamp: float        # 捕获时间戳
    raw_packet: Any     # 原始 Scapy 包对象
    
    def __repr__(self) -> str:
        return f"PcapPacket(index={self.index}, ts={self.timestamp:.6f}, {self.raw_packet.summary()})"
    
    

@dataclass
class DecodeResult:
    text: Optional[str] = None
    encoding: Optional[str] = None
    confidence: Optional[float] = None
    is_binary: Optional[bool] = None
#----------------------------------------------------------------------------
@dataclass
class InterfaceInfo:
    """网卡信息数据类"""
    name: str                    # 系统网卡名（如 eth0、WLAN0、en0）
    friendly_name: str           # 友好名称（Windows 上可能为 "Wi-Fi"）
    ip_addresses: List[str]      # 绑定的 IP 地址列表
    mac_address: Optional[str]  # MAC 地址
    is_up: bool                 # 是否启用
    is_loopback: bool           # 是否为回环接口
    speed: Optional[int]        # 链路速度（Mbps），可能为 None
    mtu: Optional[int]          # 最大传输单元
    
    def __str__(self) -> str:
        status = "UP" if self.is_up else "DOWN"
        return f"{self.name} ({status}) | IP: {self.ip_addresses} | MAC: {self.mac_address}"






