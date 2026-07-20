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
    """HTTP 解析后的公共结果模型。"""

    method: str | None = None
    host: str | None = None
    url: str | None = None
    path: str | None = None
    query: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str | bytes | None = ""
    is_request: bool = True
    version: str | None = None
    status_text: str | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

        if self.body is None:
            self.body = ""
        elif isinstance(self.body, bytes):
            self.body = self.body.decode("utf-8", errors="replace")

        if self.user_agent is None:
            self.user_agent = self.get_header("User-Agent") or None

    def is_get(self) -> bool:
        return self.method == "GET"

    def is_post(self) -> bool:
        return self.method == "POST"

    def query_dict(self) -> dict[str, list[str]]:
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

    def content_type(self) -> str | None:
        return self.get_header("Content-Type") or None

    def __str__(self) -> str:
        if self.is_request:
            return f"HTTP {self.method} {self.path or self.url}"
        return f"HTTP {self.status_code} {self.status_text}"


# 兼容成员 B 已经使用的命名；公共数据流里统一使用 HttpInfo。
HttpParseResult = HttpInfo


def to_http_info(result: Any | None) -> HttpInfo | None:
    """把成员 B 的 HTTP 解析结果对象转换为统一的 HttpInfo。"""
    if result is None:
        return None
    if isinstance(result, HttpInfo):
        return result

    return HttpInfo(
        method=getattr(result, "method", None),
        host=getattr(result, "host", None),
        url=getattr(result, "url", None),
        path=getattr(result, "path", None),
        query=getattr(result, "query", None),
        user_agent=getattr(result, "user_agent", None),
        status_code=getattr(result, "status_code", None),
        headers=dict(getattr(result, "headers", {}) or {}),
        body=getattr(result, "body", ""),
        is_request=getattr(result, "is_request", True),
        version=getattr(result, "version", None),
        status_text=getattr(result, "status_text", None),
    )


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
    index: int|None = None
    raw_packet: Any|None = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    eth_type: Optional[str] = None
    ip_version: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_proto: Optional[str] = None
    udp_length: Optional[int] = None
    layers: List[str] = field(default_factory=list)
    def summary(self) -> str:
        parts = [
            f"[{self.interface}]",
            f"{self.protocol.value if self.protocol else 'UNKNOWN'}",
            f"{self.src_ip or self.src_mac}:{self.src_port or '-'}",
            "->",
            f"{self.dst_ip or self.dst_mac}:{self.dst_port or '-'}",
            f"({self.length} bytes)"
        ]
        return " ".join(parts)

    
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








