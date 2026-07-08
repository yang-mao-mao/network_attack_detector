from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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

