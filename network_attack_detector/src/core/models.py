from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional, Dict, List
from scapy.packet import Packet
import urllib

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
class SignatureRule:
    rule_id: str
    name: str
    category: AttackCategory
    level: AlertLevel
    protocol: Protocol
    match_type: str
    pattern: str
    target_fields: list[str] = field(default_factory=list)
    nocase: bool = True
    enabled: bool = True
    description: str = ""
    suggestion: str = ""


@dataclass
class BehaviorRule:
    rule_id: str
    name: str
    category: AttackCategory
    level: AlertLevel
    event_type: str
    window_seconds: int
    threshold: int
    group_by: list[str] = field(default_factory=list)
    condition: dict[str, Any] = field(default_factory=dict)
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

class CaptureState(Enum):
    """抓包状态的枚举类"""
    IDLE = auto()       # 空闲
    RUNNING = auto()    # 运行中
    PAUSED = auto()     # 已暂停
    STOPPED = auto()    # 已停止
    ERROR = auto()      # 出错


@dataclass
class PacketInfo:
    """解析后的数据包信息"""
    index: int = None
    timestamp: float = None
    interface: str = None
    protocol: Optional[str] = None      # TCP/UDP/ICMP/Other
    length: int = None
    raw_packet: Packet = None            # 原始 scapy 包，供深度分析
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    eth_type: Optional[str] = None
    # IP 层
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_proto: Optional[str] = None
    # TCP 层
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_window: Optional[int] = None
    # UDP 层
    udp_length: Optional[int] = None
    # HTTP 层（由 HttpParser 提供）
    http = None
    # Payload 原始与解码
    raw_payload: Optional[bytes] = None
    decoded_payload = None
    # 协议栈标识
    layers: List[str] = field(default_factory=list)
    
    def summary(self) -> str:
        parts = [
            f"[{self.interface}]",
            f"{self.protocol or 'UNKNOWN'}",
            f"{self.src_ip or self.src_mac}:{self.src_port or '-'}",
            "->",
            f"{self.dst_ip or self.dst_mac}:{self.dst_port or '-'}",
            f"({self.length} bytes)"
        ]
        return " ".join(parts)

@dataclass
class PcapPacket:
    """解析后的 pcap 数据包信息"""
    index: int              # 在文件中的序号
    timestamp: float        # 捕获时间戳
    raw_packet: Packet      # 原始 Scapy 包对象
    
    def __repr__(self) -> str:
        return f"PcapPacket(index={self.index}, ts={self.timestamp:.6f}, {self.raw_packet.summary()})"

@dataclass
class HttpParseResult:
    """HTTP 解析结果"""
    is_request: bool = False       # True=请求, False=响应
    method: Optional[str] = None   # GET/POST/PUT/DELETE/...
    host: Optional[str] = None
    url: Optional[str] = None      # 完整 URL
    path: Optional[str] = None   # 仅路径部分
    query: Optional[str] = None    # 查询字符串
    version: Optional[str] = None  # HTTP/1.1
    # 响应特有
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    
    def is_get(self) -> bool:
        return self.method == "GET"
    
    def is_post(self) -> bool:
        return self.method == "POST"
    
    def query_dict(self) -> Dict[str, list[str]]:
        """解析查询字符串为字典"""
        if not self.query:
            return {}
        return urllib.parse.parse_qs(self.query)
    
    def get_header(self, name: str, default: str = "") -> str:
        """大小写不敏感获取 header"""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return default
    
    def content_type(self) -> Optional[str]:
        return self.get_header("Content-Type") or None
    
    def __str__(self) -> str:
        if self.is_request:
            return f"HTTP {self.method} {self.path or self.url}"
        return f"HTTP {self.status_code} {self.status_text}"

@dataclass
class DecodeResult:
    text: Optional[str] = None
    encoding: Optional[str] = None
    confidence: Optional[float] = None
    is_binary: Optional[bool] = None

