from __future__ import annotations

from urllib.parse import unquote, urlsplit

from src.core.models import HttpInfo


class HttpParser:
    def parse(self, payload_text: str) -> HttpInfo | None:
        if not payload_text:
            return None

        head, _, body = payload_text.partition("\r\n\r\n")
        if not head:
            head, _, body = payload_text.partition("\n\n")

        lines = head.splitlines()
        if not lines:
            return None

        first_line = lines[0].strip()
        parts = first_line.split()
        if len(parts) < 2:
            return None

        method = parts[0].upper()
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            return None

        raw_url = parts[1]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        split = urlsplit(raw_url)
        return HttpInfo(
            method=method,
            host=headers.get("host"),
            url=unquote(raw_url),
            path=unquote(split.path or raw_url),
            query=unquote(split.query),
            user_agent=headers.get("user-agent"),
            headers=headers,
            body=unquote(body),
        )

