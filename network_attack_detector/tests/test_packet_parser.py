from src.core.models import Protocol
from src.parser.packet_parser import PacketParser


def test_parse_http_bytes():
    packet = PacketParser().parse_http_bytes(
        b"GET / HTTP/1.1\r\nHost: demo.local\r\n\r\n"
    )
    assert packet.protocol == Protocol.HTTP
    assert packet.http is not None

