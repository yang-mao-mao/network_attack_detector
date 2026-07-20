from pathlib import Path
from typing import Iterator, Optional, List, Callable
from dataclasses import dataclass

from scapy.all import rdpcap, PcapReader as ScapyPcapReader
from scapy.packet import Packet

@dataclass
class PcapPacket:
    """解析后的 pcap 数据包信息"""
    index: int              # 在文件中的序号
    timestamp: float        # 捕获时间戳
    raw_packet: Packet      # 原始 Scapy 包对象
    
    def __repr__(self) -> str:
        return f"PcapPacket(index={self.index}, ts={self.timestamp:.6f}, {self.raw_packet.summary()})"

class PcapReader:
    """
    读取 pcap 文件，支持迭代、过滤、批量处理。
    包装 scapy 的 rdpcap / PcapReader，提供更友好的接口。
    """
    
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"pcap 文件不存在: {self.path}")
        
        self._packets: Optional[List[Packet]] = None  # 懒加载缓存
    
    def read_all(self) -> List[Packet]:
        """一次性读取所有包到内存（适合小文件）"""
        if self._packets is None:
            self._packets = rdpcap(str(self.path))
        return self._packets
    
    def stream(self) -> Iterator[PcapPacket]:
        """
        流式读取，不占用大量内存（适合大文件）。
        逐包 yield，用完后立即释放。
        """
        reader = ScapyPcapReader(str(self.path))
        try:
            for idx, packet in enumerate(reader, start=1):
                yield PcapPacket(
                    index=idx,
                    timestamp=float(packet.time),
                    raw_packet=packet
                )
        finally:
            reader.close()
    
    def __iter__(self) -> Iterator[PcapPacket]:
        """支持 for pkt in reader: 语法"""
        return self.stream()
    
    def __len__(self) -> int:
        """获取总包数（需要遍历一次，有开销）"""
        count = 0
        for _ in self.stream():
            count += 1
        return count
    
    def filter(self, predicate: Callable[[PcapPacket], bool]) -> Iterator[PcapPacket]:
        """
        条件过滤，只返回满足条件的包。
        
        示例:
            reader.filter(lambda p: p.raw_packet.haslayer("TCP"))
        """
        for pkt in self.stream():
            if predicate(pkt):
                yield pkt
    
    def find_first(self, predicate: Callable[[PcapPacket], bool]) -> Optional[PcapPacket]:
        """找到第一个满足条件的包"""
        for pkt in self.stream():
            if predicate(pkt):
                return pkt
        return None
    
    def slice(self, start: int = 0, end: Optional[int] = None, step: int = 1) -> Iterator[PcapPacket]:
        """
        切片读取，类似 list[start:end:step]。
        
        示例:
            reader.slice(100, 200)      # 第 100-199 个包
            reader.slice(0, None, 10)   # 每 10 个取一个
        """
        idx = 0
        for pkt in self.stream():
            if idx < start:
                idx += 1
                continue
            if end is not None and idx >= end:
                break
            if (idx - start) % step == 0:
                yield pkt
            idx += 1
    
    def stats(self) -> dict:
        """快速统计包数量和协议分布"""
        total = 0
        proto_counts = {}
        
        for pkt in self.stream():
            total += 1
            # 获取最高层协议名
            layer = pkt.raw_packet.lastlayer().name
            proto_counts[layer] = proto_counts.get(layer, 0) + 1
        
        return {
            "file": str(self.path),
            "total_packets": total,
            "protocols": proto_counts
        }
    
    def time_range(self) -> tuple[float, float] | None:
        """获取捕获时间范围"""
        first = last = None
        for pkt in self.stream():
            if first is None:
                first = last = pkt.timestamp
            else:
                last = pkt.timestamp
        return (first, last) if first is not None else None
    
    def tcp_stream(self) -> Iterator[PcapPacket]:
        """只返回 TCP 包"""
        return self.filter(lambda p: p.raw_packet.haslayer("TCP"))
    
    def udp_stream(self) -> Iterator[PcapPacket]:
        """只返回 UDP 包"""
        return self.filter(lambda p: p.raw_packet.haslayer("UDP"))
    
    def http_packets(self) -> Iterator[PcapPacket]:
        """只返回疑似 HTTP 的包（TCP 80/8080 端口）"""
        def is_http(p: PcapPacket) -> bool:
            if not p.raw_packet.haslayer("TCP"):
                return False
            tcp = p.raw_packet["TCP"]
            return tcp.dport in (80, 8080) or tcp.sport in (80, 8080)
        return self.filter(is_http)
    
    def ip_between(self, ip1: str, ip2: str) -> Iterator[PcapPacket]:
        """两个 IP 之间的通信"""
        pair = {ip1, ip2}
        return self.filter(
            lambda p: p.raw_packet.haslayer("IP") and 
                      {p.raw_packet["IP"].src, p.raw_packet["IP"].dst} == pair
        )

if __name__ == "__main__":
    # 1. 创建读取器
    reader = PcapReader("pkg.pcap")
    
    # 2. 流式读取（大文件友好）
    print("=== 流式读取前 5 个包 ===")
    for pkt in reader.stream():
        print(f"  #{pkt.index} {pkt.raw_packet.summary()}")
        if pkt.index >= 5:
            break
    
    # 3. 过滤 TCP 包
    print("\n=== TCP 包 ===")
    for pkt in reader.tcp_stream():
        print(f"  {pkt}")
        if pkt.index >= 3:
            break
    
    # 4. 自定义过滤：找 SYN 包
    print("\n=== SYN 包 ===")
    syn_packets = reader.filter(
        lambda p: p.raw_packet.haslayer("TCP") and 
                  str(p.raw_packet["TCP"].flags) == "S"
    )
    for pkt in syn_packets:
        print(f"  {pkt}")
        if pkt.index >= 5:
            break
    
    # 5. 切片读取
    print("\n=== 第 10-15 个包 ===")
    for pkt in reader.slice(10, 15):
        print(f"  #{pkt.index} {pkt}")
    
    # 6. 统计信息
    print("\n=== 统计 ===")
    print(reader.stats())
    
    # 7. 一次性读取（小文件）
    print("\n=== 全部读取 ===")
    all_packets = reader.read_all()
    print(f"共 {len(all_packets)} 个包")
    
    # 8. 遍历语法
    print("\n=== for 语法 ===")
    for pkt in reader:   # 等价 reader.stream()
        print(f"  #{pkt.index}")
        break

