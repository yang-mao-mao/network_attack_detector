from typing import Iterator, Optional, List
from scapy.layers.inet import IP, TCP, UDP

from src.capture import PcapReader, PcapPacket, my_PacketInfo
from src.core.models import PacketInfo, HttpInfo, Protocol
from .http_parser import HttpParser
from .payload_decoder import decode_payload

class PacketParser:
    """
    解析一组 PcapPacket，提取 IP/TCP/UDP/HTTP 信息及可读 payload。
    """
    
    def __init__(self):
        self.parsed: List[my_PacketInfo] = []
        self.results: List[PacketInfo] = []
    
    def to_Pi(parsed:List[my_PacketInfo]):
        results = []
        for p in parsed:
            h = HttpInfo(
                method=p.http.method,
                host=p.http.host,
                url=p.http.url,
                path=p.http.path,
                query=p.http.query,
                user_agent=p.http.get_header("User-Agent"),
                status_code=p.http.status_code,
                headers=p.http.headers,
                body=p.http.body
            )
            result = PacketInfo(
                packet_id=p.index,
                timestamp=p.timestamp,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol=Protocol(p.protocol),
                length=p.length,
                payload=p.raw_payload,
                payload_text=p.decoded_payload,
                http=h,
                raw_summary=p.summary(),
                interface=p.interface,
                metadata=None
            )
            results.append(result)
        return results
    
    def parse(self, pcap_packets: Iterator[PcapPacket]) -> Iterator[my_PacketInfo]:
        """
        流式解析 pcap 包，逐个 yield 解析结果。
        """
        for pkt in pcap_packets:
            parsed = self._parse_single(pkt)
            if parsed:
                yield parsed
    
    def parse_all(self, pcap_packets: Iterator[PcapPacket]) -> List[my_PacketInfo]:
        """
        解析全部，返回列表。
        """
        return list(self.parse(pcap_packets))
    
    def _parse_single(self, pcap_pkt: PcapPacket) -> Optional[my_PacketInfo]:
        """解析单个 PcapPacket"""
        packet = pcap_pkt.raw_packet
        result = my_PacketInfo(
            index=pcap_pkt.index,
            timestamp=pcap_pkt.timestamp,
            layers=[layer.name for layer in packet.layers()]
        )
        
        # ===== IP 层 =====
        if packet.haslayer(IP):
            ip = packet[IP]
            result.src_ip = ip.src
            result.dst_ip = ip.dst
            result.ip_version = ip.version
            result.ip_ttl = ip.ttl
            result.ip_proto = "TCP" if ip.proto == 6 else "UDP" if ip.proto == 17 else str(ip.proto)
        
        # ===== TCP 层 =====
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            result.src_port = tcp.sport
            result.dst_port = tcp.dport
            result.tcp_seq = tcp.seq
            result.tcp_ack = tcp.ack
            result.tcp_flags = str(tcp.flags)
            result.tcp_window = tcp.window
            result.ip_proto = "TCP"
            
            # 提取 TCP payload（不含头部）
            if packet.haslayer("Raw"):
                result.raw_payload = bytes(packet["Raw"].load)
                result.decoded_payload = decode_payload(result.raw_payload)
        
        # ===== UDP 层 =====
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            result.src_port = udp.sport
            result.dst_port = udp.dport
            result.udp_length = udp.len
            result.ip_proto = "UDP"
            
            if packet.haslayer("Raw"):
                result.raw_payload = bytes(packet["Raw"].load)
                result.decoded_payload = decode_payload(result.raw_payload)
        
        # ===== HTTP 层 =====
        http_result = HttpParser.parse(packet)
        if http_result:
            result.http = http_result
            # HTTP body 单独解码
            if http_result.body:
                result.decoded_payload = decode_payload(http_result.body)
        
        return result

# ========== 使用示例 ==========
if __name__ == "__main__":  
    # 读取 pcap
    reader = PcapReader("pkg.pcap")
    
    # 解析
    parser = PacketParser()
    parser.parsed = parser.parse_all(reader.stream())
    
    print(f"共解析 {len(parser.parsed)} 个包")
    
    # 查看 TCP 请求
    print("\n=== TCP 请求 ===")
    for req in parser.parsed:
        if req.raw_payload != None:
            print(f"  [{req.ip_proto}][{req.decoded_payload}]")