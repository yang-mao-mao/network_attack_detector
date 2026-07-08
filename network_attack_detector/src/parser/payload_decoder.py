from __future__ import annotations


def decode_payload(payload: bytes) -> str:
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return payload.decode(encoding, errors="replace")
        except LookupError:
            continue
    return repr(payload)

