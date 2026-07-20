import threading
import queue
import time
from pathlib import Path
from collections import defaultdict, deque
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from scapy.all import AsyncSniffer, Packet, get_if_list, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

class CaptureState(Enum):
    """抓包状态的枚举类"""
    IDLE = auto()       # 空闲
    RUNNING = auto()    # 运行中
    PAUSED = auto()     # 已暂停
    STOPPED = auto()    # 已停止
    ERROR = auto()      # 出错


@dataclass
class my_PacketInfo:
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

class LiveCapture:
    """
    实时抓包类，基于 scapy 的 AsyncSniffer 实现非阻塞抓包。
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        packet_count: int = 0,           # 0 = 无限
        promiscuous: bool = True,
        buffer_size: int = 65536
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size
        
        self._state = CaptureState.IDLE
        self._sniffer: Optional[AsyncSniffer] = None
        self._packet_queue: queue.Queue[my_PacketInfo] = queue.Queue()
        self._handlers: List[Callable[[my_PacketInfo], None]] = []
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        
        self._stats: Dict[str, Any] = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "dropped": 0
        }
    
    @staticmethod
    def list_interfaces() -> List[str]:
        """获取 scapy 可用的网卡列表"""
        return get_if_list()
    
    @staticmethod
    def validate_filter(bpf_filter: str) -> bool:
        """验证 BPF 过滤表达式是否合法（简单检查）"""
        # scapy 会在运行时真正验证，这里只做基础检查
        invalid_chars = set(";|&$`")
        return not any(c in bpf_filter for c in invalid_chars)
    
    
    def start(self) -> bool:
        """开始抓包"""
        with self._lock:
            if self._state == CaptureState.RUNNING:
                return False
            
            self._state = CaptureState.RUNNING
            self._stop_event.clear()
            self._pause_event.clear()
        
        # 启动后台 sniffer
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=self._on_packet_raw,
            count=self.packet_count,
            promisc=self.promiscuous,
            store=False          # 不存储，实时处理
        )
        self._sniffer.start()
        
        # 启动消费线程（处理队列中的包）
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True, name="LiveCapture-Worker")
        self._worker_thread.start()
        return True
    
    def stop(self) -> None:
        """停止抓包"""
        with self._lock:
            if self._state not in (CaptureState.RUNNING, CaptureState.PAUSED):
                return
            self._state = CaptureState.STOPPED
        
        self._stop_event.set()
        
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
    
    def pause(self) -> bool:
        """暂停抓包（停止接收新包，但保持连接）"""
        with self._lock:
            if self._state != CaptureState.RUNNING:
                return False
            self._state = CaptureState.PAUSED
        self._pause_event.set()
    
    def resume(self) -> bool:
        """恢复抓包"""
        with self._lock:
            if self._state != CaptureState.PAUSED:
                return False
            self._state = CaptureState.RUNNING
        self._pause_event.clear()
    
    # ========== 数据处理 ==========
    
    def _on_packet_raw(self, packet: Packet) -> None:
        """scapy 回调：原始包到达"""
        if not self._pause_event.is_set():
            try:
                info = self._parse_packet(packet)
                self._packet_queue.put(info, block=False)
            except queue.Full:
                with self._lock:
                    self._stats["dropped"] += 1
            except Exception as e:
                print(f"解析包出错: {e}")
    
    def _parse_packet(self, packet: Packet) -> my_PacketInfo:
        """解析 scapy 包为结构化信息"""
        # 基础信息
        timestamp = float(packet.time)
        iface = self.interface or "unknown"
        length = len(packet)
        
        # 以太网层
        src_mac = dst_mac = eth_type = None
        if packet.haslayer(Ether):
            eth = packet[Ether]
            src_mac = eth.src
            dst_mac = eth.dst
            eth_type = hex(eth.type) if eth.type else None
        
        # IP 层
        src_ip = dst_ip = protocol = None
        src_port = dst_port = None
        
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = f"IP-{ip.proto}"
        else:
            protocol = "NON-IP"
        
        return my_PacketInfo(
            timestamp=timestamp,
            interface=iface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_type=eth_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            raw_packet=packet
        )
    
    def _process_queue(self) -> None:
        """后台线程：消费队列中的包"""
        while not self._stop_event.is_set():
            try:
                info = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            
            # 更新统计
            self._update_stats(info)
            
            # 调用注册的处理函数
            for handler in self._handlers:
                try:
                    handler(info)
                except Exception as e:
                    print(f"Handler error: {e}")
    
    def _update_stats(self, info: my_PacketInfo) -> None:
        """更新统计信息"""
        with self._lock:
            self._stats["total"] += 1
            if info.protocol == "TCP":
                self._stats["tcp"] += 1
            elif info.protocol == "UDP":
                self._stats["udp"] += 1
            elif info.protocol == "ICMP":
                self._stats["icmp"] += 1
            else:
                self._stats["other"] += 1
    
    # ========== 公共 API ==========
    
    def add_handler(self, handler: Callable[[my_PacketInfo], None]) -> None:
        """注册包处理回调"""
        self._handlers.append(handler)
    
    def remove_handler(self, handler: Callable[[my_PacketInfo], None]) -> None:
        """移除包处理回调"""
        if handler in self._handlers:
            self._handlers.remove(handler)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取当前统计"""
        with self._lock:
            return self._stats.copy()
    
    @property
    def state(self) -> CaptureState:
        return self._state
    
    @property
    def queue_size(self) -> int:
        return self._packet_queue.qsize()
    
    def get_packet(self, timeout: Optional[float] = None) -> Optional[my_PacketInfo]:
        """阻塞获取一个包（用于同步消费）"""
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None


class CaptureHandlers:
    """
    常用抓包处理函数集合。
    """ 
    # ========== 日志输出 ==========
    @staticmethod
    def console_logger(show_payload: bool = False, max_payload: int = 200) -> Callable[[my_PacketInfo], None]:
        """
        打印到控制台。
        Args:
            show_payload: 是否显示原始 payload 内容
            max_payload: payload 最大显示字节数
        """
        def handler(info: my_PacketInfo) -> None:
            ts = time.strftime("%H:%M:%S", time.localtime(info.timestamp))
            line = f"[{ts}] {info.summary()}"
            print(line)
            
            if show_payload and info.raw_packet.haslayer("Raw"):
                payload = info.raw_packet["Raw"].load
                preview = payload[:max_payload]
                try:
                    text = preview.decode("utf-8", errors="replace")
                    print(f"  Payload: {text}")
                except Exception:
                    print(f"  Payload(hex): {preview.hex()}")
        
        return handler
    # ========== 数据存储 ==========
    @staticmethod
    def pcap_writer( path: str, batch_size: int = 20 ) -> Callable[[my_PacketInfo], None]:
        """
        保存为 pcap 文件（Wireshark 可读）。
        批量写入减少 IO。
        """
        buffer: List[Packet] = []
        filepath = Path(path)
        
        def handler(info: my_PacketInfo) -> None:
            buffer.append(info.raw_packet)
            
            if len(buffer) >= batch_size:
                wrpcap(str(filepath), buffer, append=filepath.exists())
                buffer.clear()
        
        def flush() -> None:
            if buffer:
                wrpcap(str(filepath), buffer, append=filepath.exists())
                buffer.clear()
        
        handler.flush = flush  # type: ignore
        handler.close = flush  # type: ignore
        return handler
    # ========== 安全检测类 ==========
    @staticmethod
    def port_scan_detector(threshold: int = 10, window: float = 60.0) -> Callable[[my_PacketInfo], None]:
        """
        检测端口扫描：单个 IP 在短时间内访问大量不同端口。
        """
        history: Dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        
        def handler(info: my_PacketInfo) -> None:
            if not info.src_ip or not info.dst_port:
                return
            
            now = time.time()
            ip = info.src_ip
            port = info.dst_port
            
            # 清理过期记录
            dq = history[ip]
            while dq and now - dq[0][0] > window:
                dq.popleft()
            
            # 记录新端口
            # 只记录 SYN 包（没有 ACK 的）
            if info.raw_packet.haslayer(TCP):
                flags = info.raw_packet[TCP].flags
                if "S" in str(flags) and "A" not in str(flags):
                    # 检查是否新端口
                    existing_ports = {p for _, p in dq}
                    if port not in existing_ports:
                        dq.append((now, port))
                        
                        if len({p for _, p in dq}) >= threshold:
                            print(f"\n[ALERT] 疑似端口扫描: {ip} 已访问 {len({p for _, p in dq})} 个端口")
        
        return handler
    
    @staticmethod
    def syn_flood_detector(threshold: int = 50, window: float = 5.0) -> Callable[[my_PacketInfo], None]:
        """
        检测 SYN Flood：大量 SYN 包无后续连接。
        """
        syn_count: Dict[str, deque[float]] = defaultdict(deque)
        
        def handler(info: my_PacketInfo) -> None:
            if info.protocol != "TCP":
                return
            
            flags = info.raw_packet[TCP].flags
            if "S" not in str(flags) or "A" in str(flags):
                return
            
            now = time.time()
            ip = info.src_ip
            
            dq = syn_count[ip]
            while dq and now - dq[0] > window:
                dq.popleft()
            
            dq.append(now)
            
            if len(dq) >= threshold:
                print(f"\n[ALERT] 疑似 SYN Flood: {ip} 在 {window}s 内发送 {len(dq)} 个 SYN")
                dq.clear()  # 防止重复报警
        
        return handler
    # ========== 流量统计类 ==========
    @staticmethod
    def bandwidth_meter(interval: int = 5) -> Callable[[my_PacketInfo], None]:
        """
        实时显示带宽（KB/s）。
        """
        traffic_log: deque[tuple[float, int]] = deque()
        last_print = [0.0]
        
        def handler(info: my_PacketInfo) -> None:
            now = time.time()
            traffic_log.append((now, info.length))
            
            # 清理过期
            while traffic_log and now - traffic_log[0][0] > interval:
                traffic_log.popleft()
            
            # 定期打印
            if now - last_print[0] >= interval:
                total = sum(size for _, size in traffic_log)
                speed = total / interval / 1024
                print(f"\r[带宽] {speed:.2f} KB/s ({len(traffic_log)} 包/{interval}s)", end="", flush=True)
                last_print[0] = now
        
        return handler

# ========== 使用示例 ==========
# sudo $(which python3) -m src.capture.live_capture
if __name__ == "__main__":
    from .interface import CaptureInterface  # 之前的类
    
    # 1. 查看可用网卡
    print("可用网卡:")
    for iface in CaptureInterface.get_interfaces(only_up=True):
        print(f"  {iface.name}: {iface.ip_addresses}")
    
    print("\nScapy 可用网卡:")
    for name in LiveCapture.list_interfaces():
        print(f"  {name}")
    
    # 2. 创建抓包实例
    capture = LiveCapture(
        interface="wlp0s20f3",      # 或 None 让 scapy 自动选择
        bpf_filter="",              # BPF 语法
        packet_count=0            # 抓 100 个包后自动停止，0=无限
    )
    
    capture.add_handler(CaptureHandlers.console_logger())
    capture.add_handler(CaptureHandlers.pcap_writer("./pkg.pcap",20))
    
    # 4. 开始抓包
    print("\n开始抓包...")
    capture.start()
    
    # 5. 主线程可以做其他事，或等待
    try:
        import time
        for i in range(20):
            time.sleep(1)
            stats = capture.get_stats()
            print(f"[{i}]Stats: {stats}")
    except KeyboardInterrupt:
        print("\n停止抓包...")
    
    # 6. 停止
    capture.stop()
    print(f"最终统计: {capture.get_stats()}")