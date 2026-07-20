import re
import urllib.parse
from typing import Optional, Dict
from dataclasses import dataclass, field

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

class HttpParser:
    """
    从原始字节流解析 HTTP 请求和响应。
    不依赖 Scapy HTTP 层，直接解析 TCP payload。
    """
    
    # 请求行: METHOD PATH HTTP/VERSION
    REQUEST_LINE = re.compile(
        rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+"
        rb"([^\s]+)\s+"
        rb"HTTP/(\d\.\d)\r\n"
    )
    
    # 响应行: HTTP/VERSION STATUS TEXT
    RESPONSE_LINE = re.compile(rb"^HTTP/(\d\.\d)\s+(\d{3})\s+([^\r\n]*)\r\n")
    
    # 头部字段: Name: Value
    HEADER = re.compile(rb"^([^:]+):\s*(.*?)\r\n")
    
    @staticmethod
    def parse(data) -> Optional[HttpParseResult]:
        """
        解析 HTTP 数据。
        """
        # 统一提取 bytes
        if hasattr(data, "load"):
            payload = bytes(data.load)
        else:
            payload = bytes(data)
        
        # 尝试解析请求
        result = HttpParser._parse_request(payload)
        if result:
            return result
        
        # 尝试解析响应
        result = HttpParser._parse_response(payload)
        if result:
            return result

        return None
    
    @staticmethod
    def _parse_request(payload: bytes) -> Optional[HttpParseResult]:
        """解析 HTTP 请求"""
        # 找到请求行和头部结束
        header_end = payload.find(b"\r\n\r\n")
        if header_end == -1:
            # 可能是分片，尝试只找第一个 \r\n
            first_line_end = payload.find(b"\r\n")
            if first_line_end == -1:
                return None
            header_end = first_line_end
        
        header_bytes = payload[:header_end + 2]  # 包含最后的 \r\n
        body = payload[header_end + 4:] if header_end + 4 < len(payload) else None
        
        # 解析请求行
        match = HttpParser.REQUEST_LINE.match(header_bytes)
        if not match:
            return None
        
        method = match.group(1).decode("ascii")
        url_path = match.group(2).decode("utf-8", errors="replace")
        version = match.group(3).decode("ascii")
        
        # 解析 headers
        headers = HttpParser._parse_headers(header_bytes[match.end():])
        
        # 解析 URL 组成部分
        parsed = urllib.parse.urlparse(url_path)
        path = parsed.path or "/"
        query = parsed.query
        
        # 从 Host header 构建完整 URL
        host = headers.get("Host", "")
        url = f"http://{host}{url_path}" if host else url_path
        
        return HttpParseResult(
            is_request=True,
            method=method,
            host=host,
            url=url,
            path=path,
            query=query,
            version=version,
            headers=headers,
            body=body
        )
    
    @staticmethod
    def _parse_response(payload: bytes) -> Optional[HttpParseResult]:
        """解析 HTTP 响应"""
        header_end = payload.find(b"\r\n\r\n")
        if header_end == -1:
            first_line_end = payload.find(b"\r\n")
            if first_line_end == -1:
                return None
            header_end = first_line_end
        
        header_bytes = payload[:header_end + 2]
        body = payload[header_end + 4:] if header_end + 4 < len(payload) else None
        
        # 解析响应行
        match = HttpParser.RESPONSE_LINE.match(header_bytes)
        if not match:
            return None
        
        version = match.group(1).decode("ascii")
        status_code = int(match.group(2).decode("ascii"))
        status_text = match.group(3).decode("utf-8", errors="replace").strip()
        
        headers = HttpParser._parse_headers(header_bytes[match.end():])
        
        return HttpParseResult(
            is_request=False,
            version=version,
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body=body
        )
    
    @staticmethod
    def _parse_headers(header_bytes: bytes) -> Dict[str, str]:
        """解析头部字段"""
        headers: Dict[str, str] = {}
        pos = 0
        
        while pos < len(header_bytes):
            # 找下一行
            line_end = header_bytes.find(b"\r\n", pos)
            if line_end == -1:
                break
            
            line = header_bytes[pos:line_end]
            pos = line_end + 2
            
            # 空行表示头部结束
            if not line:
                break
            
            # 解析 Name: Value
            match = HttpParser.HEADER.match(line + b"\r\n")
            if match:
                name = match.group(1).decode("utf-8", errors="replace").strip()
                value = match.group(2).decode("utf-8", errors="replace").strip()
                headers[name] = value
        
        return headers


# ========== 使用示例 ==========
if __name__ == "__main__":
    # 示例 1: HTTP 请求
    request = (
        b"GET /api/user?id=123&name=test HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: application/json\r\n"
        b"Cookie: session=abc123\r\n"
        b"\r\n"
    )
    
    result = HttpParser.parse(request)
    if result:
        print(f"请求: {result}")
        print(f"  Method: {result.method}")
        print(f"  Host: {result.host}")
        print(f"  Path: {result.path}")
        print(f"  Query: {result.query}")
        print(f"  Query Dict: {result.query_dict()}")
        print(f"  Cookie: {result.get_header('Cookie')}")
        print(f"  Content-Type: {result.content_type()}")
    
    # 示例 2: HTTP 响应
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 26\r\n"
        b"\r\n"
        b'{"status": "ok", "data": []}'
    )
    
    result = HttpParser.parse(response)
    if result:
        print(f"\n响应: {result}")
        print(f"  Status: {result.status_code}")
        print(f"  Body: {result.body}")
    
    # 示例 3: 非 HTTP
    not_http = b"\x16\x03\x03\x00\x7f..."  # TLS handshake
    print(f"\n非 HTTP: {HttpParser.parse(not_http)}")