import codecs
from typing import Optional

from src.core.models import DecodeResult

def decode_payload(
    payload: Optional[bytes],
    max_preview: int = 1000,
    fallback_hex: bool = True
) -> DecodeResult:
    """
    将二进制 payload 解码为可读文本。
    
    策略：
    1. 空内容 → 返回空字符串
    2. 检测 BOM → 按 BOM 编码解码
    3. 尝试 UTF-8（最常用）
    4. 尝试常见编码（GBK、Latin-1 等）
    5. 检测不可读字符比例 → 判定是否为二进制
    6. 二进制或解码失败 → 返回 hex 转义或替换解码
    """
    if not payload:
        return DecodeResult(text="",
            encoding= "empty",
            confidence=1.0)
    
    # ===== 步骤 1: 检测 BOM =====
    bom_encoding = _detect_bom(payload)
    if bom_encoding:
        try:
            text = payload[len(_get_bom_bytes(bom_encoding)):]
            decoded = text.decode(bom_encoding)
            return DecodeResult(
                text=_truncate(decoded, max_preview),
                encoding=bom_encoding,
                confidence=1.0
            )
        except Exception:
            pass
    
    # ===== 步骤 2: 尝试 UTF-8 =====
    try:
        decoded = payload.decode("utf-8")
        confidence = _calculate_confidence(decoded)
        return DecodeResult(
            text=_truncate(decoded, max_preview),
            encoding="utf-8",
            confidence=confidence,
            is_binary=confidence < 0.3
        )
    except UnicodeDecodeError:
        pass
    
    # ===== 步骤 3: 尝试常见编码 =====
    encodings = [
        ("gbk", 0.9),           # 中文
        ("gb2312", 0.85),       # 简体中文
        ("big5", 0.85),         # 繁体中文
        ("shift_jis", 0.85),    # 日文
        ("euc-kr", 0.85),       # 韩文
        ("latin-1", 0.5),       # 西欧，单字节不会失败
        ("cp1252", 0.5),        # Windows 西欧
    ]
    
    for enc, base_conf in encodings:
        try:
            decoded = payload.decode(enc)
            confidence = _calculate_confidence(decoded) * base_conf
            return DecodeResult(
                text=_truncate(decoded, max_preview),
                encoding=enc,
                confidence=confidence,
                is_binary=confidence < 0.3
            )
        except (UnicodeDecodeError, LookupError):
            continue
    
    # ===== 步骤 4: 全部失败，按二进制处理 =====
    if fallback_hex:
        # 可打印字符保留，其余转 \xHH
        text = "".join(
            chr(b) if 32 <= b < 127 else f"\\x{b:02x}"
            for b in payload
        )
        return DecodeResult(
            text=_truncate(text, max_preview),
            encoding="hex-escaped",
            confidence=0.1,
            is_binary=True
        )
    else:
        # 用 latin-1 强制解码（单字节，永不失败）
        decoded = payload.decode("latin-1")
        return DecodeResult(
            text=_truncate(decoded, max_preview),
            encoding="latin-1-forced",
            confidence=0.1,
            is_binary=True
        )


# ========== 辅助函数 ==========

def _detect_bom(data: bytes) -> Optional[str]:
    """检测字节序标记"""
    boms = [
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ]
    for bom, encoding in boms:
        if data.startswith(bom):
            return encoding
    return None


def _get_bom_bytes(encoding: str) -> bytes:
    """获取编码对应的 BOM 字节"""
    mapping = {
        "utf-8-sig": codecs.BOM_UTF8,
        "utf-32-le": codecs.BOM_UTF32_LE,
        "utf-32-be": codecs.BOM_UTF32_BE,
        "utf-16-le": codecs.BOM_UTF16_LE,
        "utf-16-be": codecs.BOM_UTF16_BE,
    }
    return mapping.get(encoding, b"")


def _calculate_confidence(text: str) -> float:
    """
    计算文本可读性置信度。
    基于可打印字符、空白字符、常见标点的比例。
    """
    if not text or len(text) == 0:
        return 1.0
    
    # 可打印字符（含中文等多字节字符）
    printable = sum(1 for c in text if c.isprintable() or c.isspace())
    
    # 常见控制字符允许（换行、回车、制表符）
    allowed_control = {"\n", "\r", "\t"}
    bad_control = sum(1 for c in text if ord(c) < 32 and c not in allowed_control)
    
    ratio = (printable - bad_control * 2) / len(text)
    return max(0.0, min(1.0, ratio))


def _truncate(text: str, max_len: int) -> str:
    """截断超长文本，保留首尾"""
    if len(text) <= max_len:
        return text
    
    half = max_len // 2 - 10
    return f"{text[:half]}... [{len(text)} bytes] ...{text[-half:]}"

# ========== 使用示例 ==========
if __name__ == "__main__":
    # 1. UTF-8 文本
    utf8_data = b"Hello, \xe4\xb8\x96\xe7\x95\x8c!"  # "Hello, 世界!"
    result = decode_payload(utf8_data)
    print(f"UTF-8: {result}")
    
    # 2. GBK 中文
    gbk_data = "你好，世界".encode("gbk")
    result = decode_payload(gbk_data)
    print(f"GBK: {result}")
    
    # 3. 二进制数据
    binary_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    result = decode_payload(binary_data)
    print(f"Binary: {result}")
    print(f"  is_binary={result.is_binary}")
    
    # 4. HTTP body（JSON）
    json_data = b'{"code":200,"message":"\\u6210\\u529f"}'
    result = decode_payload(json_data)
    print(f"JSON: {result}")
    
    # 5. 空数据
    result = decode_payload(b"")
    print(f"Empty: {result}")
    
    # 6. 带 BOM 的 UTF-8
    bom_data = codecs.BOM_UTF8 + "BOM text".encode("utf-8")
    result = decode_payload(bom_data)
    print(f"BOM: {result}")