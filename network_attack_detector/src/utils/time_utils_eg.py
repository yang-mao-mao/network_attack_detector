from __future__ import annotations

import time
from datetime import datetime


DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def now_ts() -> float:
    """Return the current Unix timestamp in seconds."""
    return time.time()


def now_ms() -> int:
    """Return the current Unix timestamp in milliseconds."""
    return int(now_ts() * 1000)

#fromtimestamp()方法，将时间戳转换为时间对象
def format_ts(timestamp: float, fmt: str = DEFAULT_DATETIME_FORMAT) -> str:
    """Format a Unix timestamp as local time."""
    return datetime.fromtimestamp(timestamp).strftime(fmt)


def parse_ts(value: str, fmt: str = DEFAULT_DATETIME_FORMAT) -> float:
    """Parse a formatted local time string back to a Unix timestamp."""
    return datetime.strptime(value, fmt).timestamp()


def current_time_str(fmt: str = DEFAULT_DATETIME_FORMAT) -> str:
    """Return the current local time as a formatted string."""
    return format_ts(now_ts(), fmt)
